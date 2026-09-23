import unittest

from recursive_json_search import json_search
from test_data import data, key1, key2


class json_search_test(unittest.TestCase):
    """Test module to test search function in recursive_json_search.py."""

    def test_search_found(self):
        """key should be found, return list should not be empty"""
        self.assertTrue([] != json_search(key1, data))

    def test_search_not_found(self):
        """key should not be found, should return an empty list"""
        self.assertTrue([] == json_search(key2, data))

    def test_is_a_list(self):
        """Should return a list"""
        self.assertIsInstance(json_search(key1, data), list)

    def test_wrong_role_cannot_read_secret(self):
        """viewer role must not read apiKey"""
        result = json_search("apiKey", data, role="viewer")
        self.assertEqual([], result)

    def test_operator_cannot_read_admin_secret(self):
        """operator role must not read apiKey"""
        result = json_search("apiKey", data, role="operator")
        self.assertEqual([], result)

    def test_viewer_cannot_read_management_ip(self):
        """viewer role must not read managementIpAddress"""
        result = json_search("managementIpAddress", data, role="viewer")
        self.assertEqual([], result)

    def test_admin_can_read_secret(self):
        """admin role should read apiKey"""
        result = json_search("apiKey", data, role="admin")
        self.assertTrue([] != result)

    def test_operator_can_read_management_ip(self):
        """operator role should read managementIpAddress"""
        result = json_search("managementIpAddress", data, role="operator")
        self.assertTrue([] != result)


if __name__ == "__main__":
    unittest.main()
