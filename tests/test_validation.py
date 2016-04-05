import sys
import unittest
import logging
import mvmt as mvmt


class IsValidDomain(unittest.TestCase):

	def test_valid_domain(self):
		domain = 'www.example.com'
		result = mvmt.is_valid_domain(domain)
		self.assertTrue(result)
		domain = 'www.example.co.uk'
		result = mvmt.is_valid_domain(domain)
		self.assertTrue(result)

	def test_invalid_domain(self):
		domain = 'not_good_example'
		result = mvmt.is_valid_domain(domain)
		self.assertFalse(result)
		domain = 'not_good_example.c'
		result = mvmt.is_valid_domain(domain)
		self.assertFalse(result)

class IsValidRegion(unittest.TestCase):

	def setUp(self):
		self.valid_regions = ['us-east-1', 'us-west-2', 'us-west-1', 'eu-west-1', 'eu-central-1', 
		'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'sa-east-1']
		self.invalid_regions = ['us-eat-8', 'fake', 'not-real']

	def test_valid_region(self):
		for region in self.valid_regions:
			self.assertTrue(mvmt.is_valid_region(region))

	def test_invalid_region(self):
		for region in self.invalid_regions:
			self.assertFalse(mvmt.is_valid_region(region))


if __name__ == '__main__':
	unittest.main()