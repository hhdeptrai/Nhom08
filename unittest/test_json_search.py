import unittest
from recursive_json_search import json_search
from test_data import *
from policy import POLICY


class json_search_test(unittest.TestCase):
    def test_search_found(self):
        '''key should be found, return list should not be empty'''
        self.assertTrue([] != json_search(key1, data))

    def test_search_not_found(self):
        '''key should not be found, should return an empty list'''
        self.assertTrue([] == json_search(key2, data))

    def test_is_a_list(self):
        '''Should return a list'''
        self.assertIsInstance(json_search(key1, data), list)

    # Security tests
    def test_viewer_cannot_access_apikey(self):
        '''viewer role must not receive apiKey values'''
        result = json_search("apiKey", data, role="viewer")
        self.assertEqual(result, [])

    def test_admin_can_access_apikey(self):
        '''admin role is authorized to access apiKey'''
        result = json_search("apiKey", data, role="admin")
        self.assertTrue([] != result, "admin should be able to retrieve apiKey")

    def test_operator_cannot_access_apikey(self):
        '''operator role is not authorized for apiKey'''
        result = json_search("apiKey", data, role="operator")
        self.assertEqual(result, [])

    def test_operator_can_access_management_ip(self):
        '''operator role is authorized to access managementIpAddress'''
        result = json_search("managementIpAddress", data, role="operator")
        self.assertTrue([] != result, "operator should retrieve managementIpAddress")

    def test_viewer_cannot_access_management_ip(self):
        '''viewer role is not authorized for managementIpAddress'''
        result = json_search("managementIpAddress", data, role="viewer")
        self.assertEqual(result, [])

    def test_viewer_can_access_issue_summary(self):
        '''viewer role is authorized to access issueSummary'''
        result = json_search("issueSummary", data, role="viewer")
        self.assertTrue([] != result, "viewer should retrieve issueSummary")

    def test_unknown_role_cannot_access_sensitive(self):
        '''unknown role must not access sensitive fields'''
        result = json_search("apiKey", data, role="attacker")
        self.assertEqual(result, [])

    def test_nested_sensitive_field_blocked(self):
        '''sensitive field nested inside dict/list must still be blocked'''
        nested_data = {
            "devices": [
                {"credentials": {"apiKey": "SECRET"}}
            ]
        }
        result = json_search("apiKey", nested_data, role="viewer")
        self.assertEqual(result, [])


if __name__ == '__main__':
    unittest.main()
