import unittest
from ownline_service import service

class OwnlineServiceTests(unittest.TestCase):

    def test_validate_message(self):
        self.assertFalse(service.validate_message())