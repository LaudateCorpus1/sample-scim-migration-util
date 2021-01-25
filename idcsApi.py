'''
Copyright (c) 2021, Oracle and/or its affiliates.
Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
'''
import json
import pprint
import requests
import idcsUtils

accessToken = ''

continueOnError = False
logger = None
pp = pprint.PrettyPrinter(indent=3, width=80)

def initAccessToken(idcs):
    global accessToken
    idcsUtils.logger = logger

    # Get an access token first
    accessToken = idcsUtils.getAccessToken(idcs)
    if len(accessToken) > 0 :
        logger.info('IDCS access token obtained successfully')
        return 'success'
    else:
        return 'failure'

def syncUsers (idcs, users, appDisplayName, appRoleName, groupNames):
    global nameIdMap

    logger.info('')
    logger.info('Sync ' + str(len(users)) + ' HCM user(s) to IDCS')

    # for every HCM user passed in
    for user in users:
        result = syncUser(idcs, user, appDisplayName, appRoleName)
        if result == 'error':
            return result

    if len(groupNames) > 0:
        usernames = []
        for user in users:
            usernames.append(user['username'])
        result = addUsersToGroups(idcs, groupNames, usernames)
        return result

    return 'success'

def grantUsers(idcs, usernames, appDisplayName, appRoleNames):
    logger.info('')
    logger.info('grantUsers: granting ' + str(len(usernames)) + ' user(s) to ' + str(len(appRoleNames)) + ' role(s) in application ' + appDisplayName)

    for appRoleName in appRoleNames:
        appRoleName = appRoleName.strip()
        for username in usernames:
            username = username.strip()
            userid = idcsUtils.checkUserExists(idcs, username)
            if userid == 'error':
                return 'error'
            if len(userid) == 0:
                logger.info('grantUsers: user ' + username + ' does not exist.')
                continue

            userInRole = idcsUtils.checkUserInAppRole(idcs, userid, idcsUtils.getAppRoleIdByRoleName(idcs, appDisplayName, appRoleName))
            if userInRole == 'error':
                return 'error'
            if userInRole == 'True':
                logger.info('User ' + username + ' already in app role. Nothing to do')
                continue

            logger.info('User ' + username + ' is not in app role. Granting user to app role.')
            grantID = grantUserToAppRole(idcs, username, userid, idcsUtils.getAppIdByDisplayName(idcs, appDisplayName), idcsUtils.getAppRoleIdByRoleName(idcs, appDisplayName, appRoleName))
    return 'success'

def addUsersToGroups(idcs, groupNames, usernames):
    logger.info('')
    logger.info('addUsersToGroups: adding ' + str(len(usernames)) + ' user(s) to ' + str(len(groupNames)) + ' group(s)')

    for groupName in groupNames:
        groupName = groupName.strip()
        for username in usernames:
            username = username.strip()
            userid = idcsUtils.checkUserExists(idcs, username)
            if userid == 'error':
                return 'error'
            if len(userid) == 0:
                logger.info('grantUsers: user ' + username + ' does not exist.')
                continue

            userInRole = idcsUtils.addUserToGroup(idcs, userid, idcsUtils.getGroupIDByDisplayName(idcs, groupName))
            if userInRole == 'error':
                return 'error'
    return 'success'

def removeUsersFromGroups(idcs, groupNames, usernames):
    logger.info('')
    logger.info('removeUsersFromGroups: removing ' + str(len(usernames)) + ' user(s) from ' + str(len(groupNames)) + ' group(s)')

    for groupName in groupNames:
        groupName = groupName.strip()
        for username in usernames:
            username = username.strip()
            userid = idcsUtils.checkUserExists(idcs, username)
            if userid == 'error':
                return 'error'
            if len(userid) == 0:
                logger.info('grantUsers: user ' + username + ' does not exist.')
                continue

            userInRole = idcsUtils.removeUserFromGroup(idcs, userid, idcsUtils.getGroupIDByDisplayName(idcs, groupName))
            if userInRole == 'error':
                return 'error'
    return 'success'

def deleteUsers(idcs, usernames):
    logger.info('')
    logger.info('Delete ' + str(len(usernames)) + ' user(s) from IDCS')

    for username in usernames:
        username = username.strip()
        userID = idcsUtils.getUserIdByUsername(idcs, username)
        if len(userID) > 0:
            deleteUser(idcs, username, userID)


def syncUser(idcs, user, appDisplayName, appRoleName):

    # Check if a user exist
    logger.info('Sync user: ' + user['username'])
    userid = idcsUtils.checkUserExists(idcs, user['username'])

    if userid == 'error':
        return 'error'

    if len(userid) == 0:
        logger.info('username ' + user['username'] + ' does not exist in IDCS, creating one.')
        userid = createUser(idcs, user)
        if userid == 'error':
            return 'error'
        logger.info('username ' + user['username'] + ' has been successfully created in IDCS.')
    else:
        logger.info('username ' + user['username'] + ' already exists in IDCS, id = ' + userid)

    logger.info('Check if user ' + user['username'] + ' already granted app role : ' + appRoleName)

    if appDisplayName is None or appRoleName is None or len(appDisplayName.strip()) == 0 or len(appRoleName.strip()) == 0:
        logger.info('idcsAppDisplayName or idcsAppRoleName not specified.')
        return ''

    userInRole = idcsUtils.checkUserInAppRole(idcs, userid, idcsUtils.getAppRoleIdByRoleName(idcs, appDisplayName, appRoleName))

    if userInRole == 'error':
        return 'error'

    if userInRole == 'True':
        logger.info('User ' + user['username'] + ' already in app role. Nothing else to do')
        return 'success'

    logger.info('User ' + user['username'] + ' is not in app role. Granting user to app role.')

    grantID = grantUserToAppRole(idcs, user['username'], userid, idcsUtils.getAppIdByDisplayName(idcs, appDisplayName), idcsUtils.getAppRoleIdByRoleName(idcs, appDisplayName, appRoleName))

    return grantID

def grantUserToAppRole(idcs, username, userID, appID, appRoleID):
    body = {
        'grantee': {
            'type': 'User',
             'value': userID
        },
        'app': {
            'value': appID
        },
        'entitlement' : {
            'attributeName': 'appRoles',
            'attributeValue': appRoleID
        },
        'grantMechanism' : 'ADMINISTRATOR_TO_USER',
        'schemas': [
        'urn:ietf:params:scim:schemas:oracle:idcs:Grant'
      ]
    }

    response = requests.post( url = idcs['host'] + idcs['resourcePaths']['grants'],
                             headers = {'Authorization': 'Bearer ' + accessToken, 'Content-Type': 'application/json'},
                             json = body )

    if response.status_code != 201 :
        logger.error('Error in granting user app role in IDCS. HTTP code: ' + str(response.status_code) + '. username: ' + username + ', appRoleID: ' + appRoleID)
        return 'error'

    grantID = response.json()['id']

    return grantID

def createUser(idcs, user):
    body = {
        'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
        'name': {
            'givenName': user['firstName'],
            'familyName': user['lastName']
          },
          'userName': user['username'],
          'emails': [
            {
              'value': user['email'],
              'type': 'work',
              'primary': True
            },
            {
              'value': user['email'],
              'primary': False,
              'type': 'recovery'
            }
          ]
    }

    response = requests.post( url = idcs['host'] + idcs['resourcePaths']['users'],
                             headers = {'Authorization': 'Bearer ' + accessToken, 'Content-Type': 'application/json'},
                             json = body )

    if response.status_code != 201 :
        logger.error('Error in creating user in IDCS. username: ' + user['username'] + '. HTTP code: ' + str(response.status_code))
        return 'error'

    userid = response.json()['id']

    return userid

def deleteUser(idcs, username, userID):
    response = requests.delete( url = idcs['host'] + idcs['resourcePaths']['users'] + '/' + userID + '?forceDelete=true',
                                headers = {'Authorization': 'Bearer ' + accessToken} )
    if response.status_code == 200 or response.status_code == 204:
        logger.info("Deleted user " + username)
    else:
        logger.error("Error deleting user " + username + '. HTTP response code: ' + str(response.status_code))

def revokeUsersAppRoleGrants (idcs, appDisplayName, appRoleNames, usernames):

    logger.info('')
    logger.info('Revoke ' + str(len(usernames)) + ' user(s) from ' + str(len(appRoleNames)) + ' applicaton roles in application ' + appDisplayName)

    # find app role ids from names
    appRoleNameIdMap = {}

    for appRoleName in appRoleNames:
        appRoleID = idcsUtils.getAppRoleIdByRoleName(idcs, appDisplayName, appRoleName)
        if len(appRoleID) > 0:
            appRoleNameIdMap[appRoleName] = appRoleID

    logger.debug('Got app role ids:\n')
    logger.debug('\n' + pp.pformat(appRoleNameIdMap))

    # find user ids from usernames
    userNameIdMap = {}

    for username in usernames:
        userID = idcsUtils.getUserIdByUsername(idcs, username)
        if len(userID) > 0:
            userNameIdMap[username] = userID

    logger.debug('user ids:')
    logger.debug(userNameIdMap)

    # for each app role and username combination, find a grand id
    for itemAppRole in appRoleNameIdMap.items():
        grantIDs = idcsUtils.getGrantIDsForAppRole(idcs, itemAppRole[1], userNameIdMap.values())
        logger.info('Found ' + str(len(grantIDs)) + ' matching grants for app role ' + itemAppRole[0] + '. Start revoking')
        for grantID in grantIDs:
            idcsUtils.revokeGrant(idcs, grantID)

