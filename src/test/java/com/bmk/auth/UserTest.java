package com.bmk.auth;

import com.bmk.auth.bo.User;
import com.bmk.auth.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bmk.auth.exceptions.DuplicateUserException;
import com.bmk.auth.repository.UserRepo;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.junit.runner.RunWith;

import java.io.FileReader;
import java.io.IOException;

import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class UserTest {

    private static ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private static UserRepo userRepo;

    @InjectMocks
    private static UserService userService;

    private static User userOne;
    private static User userTwo;


    @BeforeClass
    public void init() throws IOException, DuplicateUserException {
        FileReader reader = new FileReader(System.getProperty("user.dir") + "src/test/resources/TestUser.json");
        userOne = objectMapper.readValue(reader, User.class);
        userOne = userService.addUser(userOne);

        reader = new FileReader(System.getProperty("user.dir") + "src/test/resources/TestUser2.json");
        userTwo = objectMapper.readValue(reader, User.class);
    }

    @Test(expected = DuplicateUserException.class)
    public void duplicateUserCheck() throws DuplicateUserException{
        when(userService.addUser(userOne)).thenReturn(null);
    }

    @Test
    public void signUpTest() throws DuplicateUserException{
        User actualResult = userService.addUser(userTwo);
        Assert.assertTrue(userTwo.getEmail().equals(actualResult.getEmail()));
        Assert.assertFalse(userTwo.getPassword().equals(actualResult.getPassword()));
    }

    @Test
    public void invalidUserSearchTest(){
        when(userRepo.findByEmail(userTwo.getEmail())).thenReturn(null);
    }

    @Test
    public void validUserSearchTest(){
        User user = userRepo.findByEmail(userOne.getEmail());
        Assert.assertTrue(user.getEmail().equals(userOne.getEmail()));
    }
}