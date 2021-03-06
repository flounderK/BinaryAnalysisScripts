#!/usr/bin/pypy3

import angr
import numpy
import logging
import zlib
import pickle

l = logging.getLogger(__name__)
l.addHandler(logging.StreamHandler())
l.setLevel(logging.DEBUG)




class CFGExtraAnalysis:

    def __init__(self, cfg):
        self.cfg = cfg
        self.filename = cfg.project.filename
        # Remove duplicate functions (plt and got entries both populate)
        # we want something to use as a reference for colum/row indices
        self.functions = list(set(cfg.functions.values()))
        # function_names = list(set(f.name for f in self.functions.values()))
        # self.fn_n_ind = function_names.index
        num_functions = len(self.functions)
        # x = calling_func
        # y = called_func
        # this is a stupid way to create a matrix, but it prevents duplicate lists
        empty_row = [0]*num_functions
        function_call_matrix = []
        for _ in empty_row:
            function_call_matrix.append(empty_row.copy())
        self.function_call_matrix = function_call_matrix
        # looks bad, but supports pickling
        self.direct_call_matrix = None if not hasattr(self, 'direct_call_matrix') else self.direct_call_matrix
        self.indirect_call_matrix = None if not hasattr(self, 'indirect_call_matrix') else self.indirect_call_matrix

    @staticmethod
    def create_indirect_call_matrix(m):
        """Create a boolean matrix to show which functions are called
        indirectly by another function.
        m: matrix"""
        max_power = len(m.tolist()[0])
        m0 = m.copy()
        # the mask to show
        mask = m.copy()
        for i in range(0, max_power):
            m0 = m @ m0
            mask = m0 | mask
            # really gross conversion to binary matrix here, but the cpu on
            # my laptop can only hold on for so long
            mask = mask > 0
            mask = mask.astype(numpy.int)

        B = mask > 0
        return B.astype(numpy.int)

    def create_direct_call_matrix(self):
        # create an initial matrix to represent caller functions
        # and the functions called by them
        func_ind = self.functions.index
        for func in self.cfg.functions.values():
            calling_func_ind = func_ind(func)
            called_functions = set()
            app = called_functions.add
            for call_site in func.get_call_sites():
                call_target = func.get_call_target(call_site)
                call_target_func = self.cfg.functions[call_target]
                app(call_target_func)

            print(func.name + ':')

            for called_func in called_functions:
                print(called_func.name)
                called_func_ind = func_ind(called_func)
                self.function_call_matrix[called_func_ind][calling_func_ind] = 1

            print()

        self.direct_call_matrix = numpy.matrix(self.function_call_matrix)

    def create_own_indirect_call_matrix(self):
        if self.direct_call_matrix is None:
            self.create_direct_call_matrix()
        # Completely ignore computational complexity, just throw around
        # dot products like we're rolling in spare processors
        self.indirect_call_matrix = self.create_indirect_call_matrix(self.direct_call_matrix)

    def call_check(self, caller, called):
        """Check for an indirect or direct call from caller to called"""
        caller_ind = self.functions.index(self.cfg.functions[caller])
        called_ind = self.functions.index(self.cfg.functions[called])
        return bool(self.indirect_call_matrix[called_ind].item(caller_ind))

    def direct_call_check(self, caller, called):
        """Check for a direct call from caller to called"""
        caller_ind = self.functions.index(self.cfg.functions[caller])
        called_ind = self.functions.index(self.cfg.functions[called])
        return bool(self.direct_call_matrix[called_ind].item(caller_ind))

    @staticmethod
    def print_matrix(matrix):
        m = matrix
        if isinstance(matrix, numpy.matrix):
            m = m.tolist()
        for r in m:
            print(' '.join(str(c) for c in r))


    def __getstate__(self):
        d = dict((k, v) for k, v in self.__dict__.items() if k not in {'cfg', 'functions'})
        pickled = pickle.dumps(d)
        compressed = zlib.compress(pickled)
        return compressed

    def __setstate__(self, s):
        pickled = zlib.decompress(s)
        data = pickle.loads(pickled)
        self.__dict__.update(data)


    def _cfg_restore(self, cfg):
        """To recover cfg after being unpickled"""
        self.__init__(cfg)


# if __name__ == '__main__':
#     import argparse
#     parser = argparse.ArgumentParser()
#     parser.add_argument('binary', help='Binary to analyze')
#     parser.add_argument('-l', '--auto-load-libs', action='store_true', default=False,
#                         help='Tell angr to load shared objects. This will take longer')
#
#     args = parser.parse_args()
#     project = angr.Project(args.binary, auto_load_libs=args.auto_load_libs)
#
#     cfg = project.analyses.CFG()
#     c = CFGExtraAnalysis(cfg)
#     c.call_check('caller', 'called')
#     c.call_check(0x400248, 'called')
