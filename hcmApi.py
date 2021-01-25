'''
Copyright (c) 2021, Oracle and/or its affiliates.
Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
'''
import json
import pprint
import requests
import urllib.parse

continueOnError = False
logger = None
pp = pprint.PrettyPrinter(indent=3, width=80)

def getUsersByRole(hcm, filterString):

    logger.info('')
    logger.info('Get HCM user IDs by Role')

    response = requests.get( url = hcm['host'] + hcm['resourcePaths']['roles'] + '?filter=' + urllib.parse.quote(filterString),
                            auth = (hcm['username'], hcm['password']) )

    if response.status_code != 200 :
        logger.error('Error in getting user IDs by role in HCM. HTTP code: ' + str(response.status_code) + '. filter string: ' + filterString)
        return []

    responseBody = response.json()

    userIDs = []
    for item in responseBody['Resources']:
        for member in item['members']:
            userIDs.append(member['value'])

    logger.info('Found ' + str(len(userIDs)) + ' user(s) in role in HCM')

    users = _getUsersByIDs(hcm, userIDs)
    return users

def getUsersByUsernames(hcm, usernames):
    users = []

    for username in usernames:
        response = requests.get( url = hcm['host'] + hcm['resourcePaths']['users'] + '?filter=userName eq "' + username + '"',
                                 auth = (hcm['username'], hcm['password']) )

        if response.status_code == 200 :
            users.append( _extractSingleUserInfo(response.json()['Resources'][0]) )
        else :
            logger.error('Error in retrieving single HCM user ' + username + '. HTTP code: ' + str(response.status_code))
            if continueOnError :
                logger.info('Continue')
            else:
                logger.info('Stop processing. Returning all retrieved HCM users')
                return users

    return users


def _getUsersByIDs(hcm, userIDs):
    users = []
    for userID in userIDs:
        response = requests.get( url = hcm['host'] + hcm['resourcePaths']['users'] + '/' + userID,
                                 auth = (hcm['username'], hcm['password']) )
        if response.status_code == 200 :
            users.append( _extractSingleUserInfo(response.json()) )
        else :
            logger.error('Error in retrieving single HCM user. HTTP code: ' + str(response.status_code))
            if continueOnError :
                logger.info('Continue')
            else:
                logger.info('Stop processing. Returning all retrieved HCM users')
                return users

    return users

def _extractSingleUserInfo(userData):
    user = {}
    user['username'] = userData['userName']
    user['firstName'] = userData['name']['givenName']
    user['lastName'] = userData['name']['familyName']
    user['displayName'] = userData['displayName']
    user['email'] = userData['emails'][0]['value']
    return user


