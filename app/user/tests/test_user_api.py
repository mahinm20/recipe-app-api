from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status

CREATE_USER_URL = reverse('user:create')
TOKEN_URL = reverse('user:token')
ME_URL = reverse('user:me')

def create_user(**params):
    return get_user_model().objects.create_user(**params)



class PublicUserAPITest(TestCase):
    """Test the user api(public)"""

    def setUp(self):
        self.client = APIClient()

    def test_create_valid_user_success(self):
        """Test creating user with valid payloads success"""
        payload = {
        'email':'testmail@gmail.com',
        'password' : 'testpasword',
        'name' : 'Frank Costanza'
        }

        res = self.client.post(CREATE_USER_URL,payload)
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(**res.data)
        self.assertTrue(
            user.check_password(payload['password'])
        )
        self.assertNotIn('password', res.data)

    def test_user_exists(self):
        """ Test creating user if it already exists"""

        payload = {'email' : 'testmail2@gmail.com', 'password':'testpassword'}
        create_user(**payload)
        res= self.client.post(CREATE_USER_URL,payload)
        self.assertTrue(res.status_code,status.HTTP_400_BAD_REQUEST)


    def test_password_too_short(self):
        """Test that password must be more than 5 characters"""
        payload = {'email': 'test@londonappdev.com', 'password': 'pw'}
        res = self.client.post(CREATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        user_exists = get_user_model().objects.filter(
            email=payload['email']
        ).exists()
        self.assertFalse(user_exists)

    def test_create_token_for_user(self):
        """Test that a token is create for user"""
        payload = {'email':'test@loda.com','password':'abc123'}
        create_user(**payload)
        res = self.client.post(TOKEN_URL,payload)
        self.assertIn('token',res.data)
        self.assertEqual(res.status_code,status.HTTP_200_OK)


    def test_create_token_invalid_credentials(self):
        """" test that token what is not created if invalid credentials are used"""
        create_user(email='test@loda.com',password='testpass')
        payload= {'email':'test@loda.com','password':'wrong'}
        res = self.client.post(TOKEN_URL, payload)

        self.assertNotIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_token_no_user(self):
        """ test that token is not created  when user doesn't exists"""
        payload = {'email':'test@loda.com','password':'abc123'}
        res = self.client.post(TOKEN_URL, payload)

        self.assertNotIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_token_missing_field(self):
        """ test token not created when wrong credentials """

        res = self.client.post(TOKEN_URL, {'email': 'lolol', 'password': ''})
        self.assertNotIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)


    def test_retrieve_user_unauth(self):
        """ Test that authentication is rwquired for users"""

        res = self.client.post(ME_URL)
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)



class PrivateUserAPITest(TestCase):
    """Test api request that require authentication"""
    def setUp(self):
        self.user = create_user(
        email = 'abctest@mahin.com',
        password = 'helloworld',
        name = 'Tester'
        )
        self.client = APIClient()
        self.client.force_authenticate(user = self.user)

    # def test_retrieve_profile_success(self):
    #     """ test retrieving profile for logged in usec"""
    #     res = self.client.post(ME_URL)
    #     self.assertEqual(res.status_code, status.HTTP_200_OK)
    #
    #     #user object return is what we expect
    #     self.assertEqual(res.data, {
    #         'name': self.user.name,
    #         'email': self.user.email,
    #     })
    def test_retrieve_profile_success(self):
        """Test retrieving profile for logged in user"""
        res = self.client.get(ME_URL)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data, {
            'name': self.user.name,
            'email': self.user.email,
        })



    def test_post_not_allowed_on_me(self):
        """ test that post is not allowed on ME url """
        res= self.client.post(ME_URL,{})
        self.assertEqual(res.status_code,status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_update_user_profile(self):
        """ test updating user profile for auth user"""
        payload = {'name':'anakin','password':'anakinsky'}
        res = self.client.patch(ME_URL,payload)

        self.user.refresh_from_db()
        self.assertEqual(self.user.name, payload['name'])
        self.assertTrue(self.user.check_password(payload['password']))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
