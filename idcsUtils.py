'''
Copyright (c) 2021, Oracle and/or its affiliates.
Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
'''

import json
import pprint
import configparser
import requests
import urllib.parse
import idcsApi

accessToken = ''
logger = None

nameIdMap = {}

pp = pprint.PrettyPrinter(indent=3, width=80)

def getAccessToken(idcs):
    global accessToken

    body = {}
    body['grant_type'] = 'password'
    body['scope'] = 'urn:opc:idm:__myscopes__'
    body['username'] = idcs['username']
    body['password'] = idcs['password']

    response = requests.post( url = idcs['host'] + idcs['resourcePaths']['token'],
                              auth = (idcs['clientID'], idcs['clientSecret']),
                              headers = {'Content-Type': 'application/x-www-form-urlencoded'},
                              data = body )

    if response.status_code == 200 :
        accessToken = response.json()['access_token']
        logger.debug('Token\n: ' + accessToken)
    else :
        logger.error('Error in obtaining access token from IDCS. HTTP code: ' + str(response.status_code))
    return accessToken

def checkUserInAppRole(idcs, userID, appRoleID):

    response = requests.get( url = idcs['host'] + idcs['resourcePaths']['approles'] + '/' + appRoleID + '?attributes=' + urllib.parse.quote('members[type eq "User"]'),
                             headers = {'Authorization': 'Bearer ' + accessToken} )

    if response.status_code != 200 :
        logger.error('Error in checking user in app role. userID: ' + userID + ', appRoleID: ' + appRoleID + '. HTTP code: ' + str(response.status_code))
        return 'error'

    responseBody = response.json()
    for member in responseBody['members']:
        if member['value'] == userID:
            return "True"

    return "False";

def addUserToGroup(idcs, userID, groupID):

    body = {}
    body['schemas'] = ['urn:ietf:params:scim:api:messages:2.0:PatchOp']
    body['Operations'] = [{}]
    body['Operations'][0]['op'] = 'add'
    body['Operations'][0]['path'] = 'members'
    body['Operations'][0]['value'] = [{}]
    body['Operations'][0]['value'][0]['value'] = userID
    body['Operations'][0]['value'][0]['type'] = 'User'

    logger.debug('Adding user to group body:')
    logger.debug(json.dumps(body))

    urlString = idcs['host'] + idcs['resourcePaths']['groups'] + '/' + groupID
    logger.debug(urlString)

    response = requests.patch( url = urlString,
                               headers = {'Authorization': 'Bearer ' + accessToken,
                                          'Content-Type': 'application/json',
                                          'Accept': '*/*',
                                          'Accept-Encoding': 'gzip, deflate, br'},
                               data = json.dumps(body) )

    if response.status_code != 200 :
        logger.error('Error in adding user to group. userID: ' + userID + ', groupID: ' + groupID + '. HTTP code: ' + str(response.status_code))
        logger.error(response)
        return 'error'

    return 'success'

def removeUserFromGroup(idcs, userID, groupID):

    body = {}
    body['schemas'] = ['urn:ietf:params:scim:api:messages:2.0:PatchOp']
    body['Operations'] = [{}]
    body['Operations'][0]['op'] = 'remove'
    body['Operations'][0]['path'] = 'members[value eq "' + userID + '"]'

    logger.debug('Removing user from group body:')
    logger.debug(json.dumps(body))

    urlString = idcs['host'] + idcs['resourcePaths']['groups'] + '/' + groupID
    logger.debug(urlString)

    response = requests.patch( url = urlString,
                               headers = {'Authorization': 'Bearer ' + accessToken,
                                          'Content-Type': 'application/json',
                                          'Accept': '*/*',
                                          'Accept-Encoding': 'gzip, deflate, br'},
                               data = json.dumps(body) )

    if response.status_code != 200 :
        logger.error('Error in removing user from group. userID: ' + userID + ', groupID: ' + groupID + '. HTTP code: ' + str(response.status_code))
        logger.error(response)
        return 'error'

    return 'success'

def checkUserExists(idcs, username):

    response = requests.get( url = idcs['host'] + idcs['resourcePaths']['users'] + '?filter=' + urllib.parse.quote('userName eq "' + username +'"'),
                             headers = {'Authorization': 'Bearer ' + accessToken} )

    responseBody = response.json()
    if response.status_code == 200 :
        totalResult = responseBody['totalResults']
        if totalResult > 0:
            return responseBody['Resources'][0]['id']
        else:
            return ''
    else :
        logger.error('Error in checking user existance. username: ' + username + ', HTTP code: ' + str(response.status_code))
        return 'error'

def getAppIdByDisplayName(idcs, appDisplayName):
    global nameIdMap

    prefix = 'app:'

    if prefix+appDisplayName in nameIdMap and len(nameIdMap[prefix + appDisplayName]) > 0:
        return nameIdMap[prefix + appDisplayName]

    response = requests.get( url = idcs['host'] + idcs['resourcePaths']['apps'] + '?filter=' + urllib.parse.quote('displayName eq "' + appDisplayName +'"'),
                             headers = {'Authorization': 'Bearer ' + accessToken} )

    responseBody = response.json()
    if response.status_code == 200 :
        totalResult = responseBody['totalResults']
        if totalResult > 0:
            appID = responseBody['Resources'][0]['id']
            nameIdMap[prefix + appDisplayName] = appID
            return appID
        else:
            return ''
    else :
        logger.error('Error in getting app id for app: ' + appDisplayName + ', HTTP code: ' + str(response.status_code))
        return 'error'

def getAppRoleIdByRoleName(idcs, appDisplayName, appRoleName):
    global nameIdMap

    prefix = appDisplayName + ':'

    if prefix+appRoleName in nameIdMap and len(nameIdMap[prefix + appRoleName]) > 0:
        return nameIdMap[prefix + appRoleName]

    response = requests.get( url = idcs['host'] + idcs['resourcePaths']['approles'] + '?filter=' + urllib.parse.quote('displayName eq "' + appRoleName + '" and app[display eq "' + appDisplayName + '"]'),
                             headers = {'Authorization': 'Bearer ' + accessToken} )

    responseBody = response.json()
    if response.status_code == 200 :
        totalResult = responseBody['totalResults']
        if totalResult > 0:
            appRoleID = responseBody['Resources'][0]['id']
            nameIdMap[prefix + appRoleName] = appRoleID
            return appRoleID
        else:
            return ''
    else :
        logger.error('Error in getting app role id for app and app role: ' + appDisplayName + '. ' + appRoleName + '. HTTP code: ' + str(response.status_code))
        return 'error'

def getUserIdByUsername(idcs, username):
    global nameIdMap

    prefix = 'user:'

    if prefix+username in nameIdMap and len(nameIdMap[prefix + username]) > 0:
        return nameIdMap[prefix + username]

    response = requests.get( url = idcs['host'] + idcs['resourcePaths']['users'] + '?filter=' + urllib.parse.quote('userName eq "' + username + '"'),
                             headers = {'Authorization': 'Bearer ' + accessToken} )

    responseBody = response.json()
    if response.status_code == 200 :
        totalResult = responseBody['totalResults']
        if totalResult > 0:
            userID = responseBody['Resources'][0]['id']
            nameIdMap[prefix + username] = userID
            return userID
    else :
        logger.error('Error in getting user id for user ' + username + '. HTTP code: ' + str(response.status_code))
        return ''

    return ''

def revokeGrant(idcs, grantID):
    response = requests.delete( url = idcs['host'] + idcs['resourcePaths']['grants'] + '/' + grantID,
                             headers = {'Authorization': 'Bearer ' + accessToken} )
    if response.status_code == 200 or response.status_code == 204:
        logger.info("Deleted grant " + grantID)
    else:
        logger.error("Error deleting grant " + grantID + '. HTTP response code: ' + str(response.status_code))

def getGrantIDsForAppRole(idcs, appRoleID, userIDs):
    grantIDs = []

    filterString = 'grantee[type eq "User"] and entitlement[attributeName eq "appRoles" and attributeValue eq "' + appRoleID + '"]'
    response = requests.get( url = idcs['host'] + idcs['resourcePaths']['grants'] + '?filter=' + urllib.parse.quote(filterString),
                             headers = {'Authorization': 'Bearer ' + accessToken} )

    if response.status_code != 200:
        logger.error("Error in getting grant IDs for app role ID: " + appRoleID + '. HTTP response code: ' + str(response.status_code))
        return grantIDs

    grants = response.json()['Resources']
    for grant in grants:
        for userid in userIDs:
            if grant['grantee']['value'] == userid:
                grantIDs.append(grant['id'])

    return grantIDs

def getGroupIDByDisplayName(idcs, groupDisplayName):
    global nameIdMap

    prefix = 'group:'

    if prefix+groupDisplayName in nameIdMap and len(nameIdMap[prefix + groupDisplayName]) > 0:
        return nameIdMap[prefix + groupDisplayName]

    response = requests.get( url = idcs['host'] + idcs['resourcePaths']['groups'] + '?filter=' + urllib.parse.quote('displayName eq "' + groupDisplayName + '"'),
                             headers = {'Authorization': 'Bearer ' + accessToken} )

    responseBody = response.json()
    if response.status_code == 200 :
        totalResult = responseBody['totalResults']
        if totalResult > 0:
            groupID = responseBody['Resources'][0]['id']
            nameIdMap[prefix + groupDisplayName] = groupID
            return groupID
    else :
        logger.error('Error in getting group id for group ' + groupDisplayName + '. HTTP code: ' + str(response.status_code))
        return ''

    return ''
