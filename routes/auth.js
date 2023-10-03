const AWS = require('aws-sdk');
const crypto = require('crypto');
const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
const {
    AuthenticationDetails,
    CognitoUser,
    CognitoUserAttribute,
    CognitoUserPool,
} = require('amazon-cognito-identity-js');
const { group } = require('console');

AWS.config.update({
    accessKeyId: process.env.ACCESS_KEY_ID,
    secretAccessKey: process.env.SECRET_ACCESS_KEY,
    region: process.env.REGION,
});

const poolData = {
    UserPoolId: process.env.USER_POOL_ID,
    ClientId: process.env.CLIENT_ID,
};

const UserPool = new CognitoUserPool(poolData);

const cognitoIdentityServiceProvider = new AWS.CognitoIdentityServiceProvider({
    region: process.env.REGION,
});


async function registerUser(req, res) {
    // Implement user registration logic
    const attributeList = [
        new CognitoUserAttribute({ Name: 'email', Value: req.body.email }),
        new CognitoUserAttribute({
            Name: 'family_name',
            Value: req.body.last_name.trim(),
        }),
        new CognitoUserAttribute({
            Name: 'given_name',
            Value: req.body.first_name.trim(),
        }),
        new CognitoUserAttribute({
            Name: 'phone_number',
            Value: req.body.mobile_phone,
        }),
        new CognitoUserAttribute({
            Name: 'preferred_username',
            Value: req.body.username,
        }),
        // new CognitoUserAttribute({
        //     Name: 'token',
        //     Value: req.body.username,
        // }),
        // new CognitoUserAttribute({
        //     Name: 'token_created_at',
        //     Value: req.body.username,
        // }),
    ];

    try {
        // TODO
        // we need to format response to match that of cognito service to avoaid breaking changes
        const signUpResult = await new Promise((resolve, reject) => {
            UserPool.signUp(
                req.body.username,
                req.body.password,
                attributeList,
                [],
                (err, result) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(result);
                    }
                }
            );
        });

        res.json({ message: 'Registration successful', signUpResult });

    } catch (error) {
        console.error('Error signing up:', error.message);
        res.status(500).json({ error: error.message });
        // throw new Error(error);
    }
}

async function authenticateUser(req, res) {
    // Implement user authentication logicc
    const params = {
        AuthFlow: 'USER_PASSWORD_AUTH',
        ClientId: process.env.CLIENT_ID,
        AuthParameters: {
            USERNAME: req.body.username,
            PASSWORD: req.body.password,
        },
    };
    try {
        const response = await cognitoIdentityServiceProvider
            .initiateAuth(params)
            .promise();
        // const sub = response.AuthenticationResult?.AccessToken?.payload?.sub;

        res.json({ message: 'Sign in successful', data: response });
    } catch (error) {
        console.error('Error signing in:', error.message);
        res.status(500).json({ error: error.message });
    }
}

async function verifyUser(req, res) {
    const params = {
        ClientId: process.env.CLIENT_ID,
        Username: req.body.username,
        ConfirmationCode: req.body.verificationCode,
    };

    try {
        await cognitoIdentityServiceProvider.confirmSignUp(params).promise();
        res.json({ message: 'User verified successfully.' });
    } catch (error) {
        console.error('Error verifying user:', error);
        res.status(500).json({ error: error.message });
    }
};

async function forgotPassword(req, res) {
    // Implement forgot password logic

    const params = {
        ClientId: process.env.CLIENT_ID,
        Username: req.body.username,
    };

    try {
        const response = await cognitoIdentityServiceProvider
            .forgotPassword(params)
            .promise();

        // Note: Cognito doesn't provide the recovery token in the response.
        // You can use the CodeDeliveryDetails from the response for further processing.
        const codeDeliveryDetails = response.CodeDeliveryDetails;

        //   SAMPLE_RESPONSE FOR codeDeliveryDetails
        //   {
        //     "CodeDeliveryDetails": {
        //       "Destination": "example@example.com",
        //       "DeliveryMedium": "EMAIL",
        //       "AttributeName": "email"
        //     }
        //   }

        res.json({ message: 'Forgot password request initiated', data: response });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}

async function resetPassword(req, res) {
    // Implement reset password logic
    const params = {
        ClientId: process.env.CLIENT_ID,
        Username: req.body.username,
        ConfirmationCode: req.body.recovery_token, // This is equivalent to the recovery token in okta
        Password: req.body.new_password,
    };

    try {
        const response = await cognitoIdentityServiceProvider
            .confirmForgotPassword(params)
            .promise();

        res.json({ message: 'Forgot password request initiated', data: response });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}

async function changePassword(req, res) {
    try {
        const params = {
            AccessToken: req.header.token,
            PreviousPassword: req.body.old_password,
            ProposedPassword: req.body.new_password,
        };

        const response = await cognitoIdentityServiceProvider
            .changePassword(params)
            .promise();

        res.json({ message: 'Change password request initiated', data: response });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}

async function getUser(req, res) {
    try {
        const params = {
            UserPoolId: process.env.USER_POOL_ID, // Replace with your Cognito User Pool ID
            Username: req.body.username, // id_or_login is the username
        };

        const user = await cognitoIdentityServiceProvider
            .adminGetUser(params)
            .promise();
        const with_groups = true
        if (with_groups) {
            const groups = [];
            const userGroups = await cognitoIdentityServiceProvider
                .adminListGroupsForUser(params)
                .promise();
            userGroups.Groups.forEach((group) => {
                groups.push(group.GroupName);
            });
            user.groups = groups;
        }

        res.json({ message: 'Change password request initiated', data: user });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}

async function updateUser(req, res) {
    const cognitoAttributes = mapAttributesToCognitoNames(req.body);

    const params = {
        UserPoolId: process.env.USER_POOL_ID,
        Username: req.body.username,
        UserAttributes: Object.entries(cognitoAttributes).map(
            ([Name, Value]) => ({
                Name,
                Value,
            })
        ),
    };

    try {
        const response = await cognitoIdentityServiceProvider
            .adminUpdateUserAttributes(params)
            .promise(); // respose must must be of same interface/type as okta implementation

        res.json({ message: 'User info updated successfully', data: response });
    } catch (error) {
        console.error('Error updating user attributes:', error);
        res.status(500).json({ error: error.message });
    }
}

async function assignUser(req, res) {
    const groupsAsMap = await listGroup();
    console.log(req.body.username.trim(), groupsAsMap);
    // groupsAsMap['theWildest'] - Retrieve group just as we have it in okta and pick the group name. Also how many group are we going to have
    const params = {
        GroupName: groupsAsMap['theWildest'],
        UserPoolId: process.env.USER_POOL_ID,
        Username: req.body.username.trim()
    };

    try {
        const response = await cognitoIdentityServiceProvider
            .adminAddUserToGroup(params)
            .promise(); // Okta return user. confirm the return value and format respose to match a specific interface type and is used across both service
        console.log(
            `User ${req.body.username} assigned to group ${groupsAsMap['theWildest']} successfully.`
        );

        res.json({ message: `User ${req.body.username} assigned to group ${groupsAsMap['theWildest']} successfully.`, data: response, groupsAsMap });
    } catch (error) {
        console.error(`Error assigning user to group: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
}

async function getUserGroup(req, res) {
    try {
        const params = {
            UserPoolId: process.env.USER_POOL_ID,
            Username: req.params.username,
        };

        const response = await cognitoIdentityServiceProvider
            .adminListGroupsForUser(params)
            .promise();

        const groups = response.Groups.map((group) => group.GroupName);

        res.json({ message: `User group retrieved.`, data: response, groups });
    } catch (error) {
        console.error('Error getting user groups:', error);
        return [];
    }
}

async function deactivateOrDeleteUser() {
    try {
        const params = {
            UserPoolId: process.env.USER_POOL_ID,
            Username: req.body.username,
        };

        return await cognitoIdentityServiceProvider
            .adminDisableUser(params)
            .promise();
        // OR
        // await cognitoIdentityServiceProvider.adminDeleteUser(params).promise();
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}

async function listGroup() {
    const result = await cognitoIdentityServiceProvider
        .listGroups({ UserPoolId: process.env.USER_POOL_ID })
        .promise();
    const groupsAsMap = {};
    result.Groups.forEach((group) => {
        groupsAsMap[group.GroupName] = group.GroupName;
    });

    return groupsAsMap;
}

function mapAttributesToCognitoNames(attributes) {
    const attributeMappings = {
        first_name: 'given_name',
        last_name: 'family_name',
        email: 'email',
        mobile_phone: 'phone_number',
    };

    const cognitoAttributes = {};

    for (const [key, value] of Object.entries(attributes)) {
        if (attributeMappings[key]) {
            cognitoAttributes[attributeMappings[key]] = value;
        }
    }

    return cognitoAttributes;
}

module.exports = { UserPool, registerUser, authenticateUser, verifyUser, forgotPassword, resetPassword, changePassword, getUser, updateUser, assignUser, getUserGroup, deactivateOrDeleteUser };



// app.post('/login', (req, res) => {
//     // Authenticate user using AWS Cognito or other authentication logic
//     // Assuming you have obtained the Cognito session token

//     // Write the Cognito session token to the cookie session
//     req.session.cognitoSessionToken = userCognitoSessionToken;

//     res.status(200).json({ message: 'Login successful' });
// });
