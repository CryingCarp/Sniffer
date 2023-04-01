import unittest
from file_operation import *

class Test_is_file_exist(unittest.TestCase):
    def test_current_exist_path(self):
        self.assertEqual(is_file_exist(), False)  # add assertion here


if __name__ == '__main__':
    unittest.main()
