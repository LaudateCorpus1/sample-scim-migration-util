'''
Copyright (c) 2021, Oracle and/or its affiliates.
Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
'''
import json
import pprint
import configparser
import hcmApi
import idcsApi
import getpass
import logging

def getHcmUsers(hcm, taskConfig):
    resourceType = taskConfig['hcmResourceType']
    if resourceType == 'roles':
        filterString = taskConfig['hcmFilterString']
        return hcmApi.getUsersByRole(hcm, filterString)
    elif resourceType == 'users':
        usernameString = taskConfig['hcmUsernames']
        usernames = usernameString.split(',')
        for ii in range(len(usernames)):
            usernames[ii] = usernames[ii].strip()

        return hcmApi.getUsersByUsernames(hcm, usernames)


def sync(hcm, idcs, taskConfig):

    hcmUsers = getHcmUsers(hcm, taskConfig)

    logger.info('Found ' + str(len(hcmUsers)) + ' HCM users:')
    logger.info('\n'+pp.pformat(hcmUsers))

    idcsGroupNames = []
    if taskConfig['idcsGroupNames'] is not None and len(taskConfig['idcsGroupNames'].strip()) > 0:
        idcsGroupNamesString = taskConfig['idcsGroupNames']
        idcsGroupNames = idcsGroupNamesString.split(',')

    syncResult = idcsApi.syncUsers(idcs, hcmUsers, taskConfig['idcsAppDisplayName'], taskConfig['idcsAppRoleName'], idcsGroupNames)
    logger.info('IDCS user sync status: ' + syncResult)

def grant(idcs, taskConfig):
    appRoleNamesString = taskConfig['idcsAppRoleNames']
    appRoleNames = appRoleNamesString.split(',')

    usernamesString = taskConfig['idcsUsernames']
    usernames = usernamesString.split(',')

    syncResult = idcsApi.grantUsers(idcs, usernames, taskConfig['idcsAppDisplayName'], appRoleNames)

    logger.info('IDCS user grant status: ' + syncResult)

def addToGroups(idcs, taskConfig):
    groupNamesString = taskConfig['idcsGroupNames']
    groupNames = groupNamesString.split(',')

    usernamesString = taskConfig['idcsUsernames']
    usernames = usernamesString.split(',')

    syncResult = idcsApi.addUsersToGroups(idcs, groupNames, usernames)

    logger.info('IDCS add users to groups status: ' + syncResult)

def removeFromGroups(idcs, taskConfig):
    groupNamesString = taskConfig['idcsGroupNames']
    groupNames = groupNamesString.split(',')

    usernamesString = taskConfig['idcsUsernames']
    usernames = usernamesString.split(',')

    syncResult = idcsApi.removeUsersFromGroups(idcs, groupNames, usernames)

    logger.info('IDCS remove users from groups status: ' + syncResult)

def deleteUsers(idcs, taskConfig):
    usernamesString = taskConfig['idcsUsernames']
    usernames = usernamesString.split(',')
    for ii in range(len(usernames)):
        usernames[ii] = usernames[ii].strip()

    idcsApi.deleteUsers(idcs, usernames)

def revoke(idcs, taskConfig):
    appRoleNamesString = taskConfig['idcsAppRoleNames']
    appRoleNames = appRoleNamesString.split(',')
    for ii in range(len(appRoleNames)):
        appRoleNames[ii] = appRoleNames[ii].strip()

    usernamesString = taskConfig['idcsUsernames']
    usernames = usernamesString.split(',')
    for ii in range(len(usernames)):
        usernames[ii] = usernames[ii].strip()

    idcsApi.revokeUsersAppRoleGrants(idcs, taskConfig['idcsAppDisplayName'], appRoleNames, usernames)

pp = pprint.PrettyPrinter(indent=3, width=80)

logFormat = '%(asctime)s--%(levelname)s: %(message)s'
logging.basicConfig(format=logFormat)
logger = logging.getLogger('hcm-idcs-usersync')
logger.setLevel(logging.INFO)

logger.info('Reading config')

config = configparser.ConfigParser()
config.read('./config')

# Get logging configuration

loggingLevel = logging.INFO
if config['DEFAULT']['loggingLevel'] is not None and config['DEFAULT']['loggingLevel'].lower() == 'debug':
    loggingLevel = logging.DEBUG

logger.setLevel(loggingLevel)
logger.info('Log level set to ' + logging.getLevelName(loggingLevel))

if config['DEFAULT']['logFileName'] is not None and len(config['DEFAULT']['logFileName']) > 0:
    fn = config['DEFAULT']['logFileName'].strip()
    fileHandler = logging.FileHandler(fn)
    fileHandler.setLevel(loggingLevel)
    fileHandler.setFormatter(logging.Formatter(logFormat))
    logger.addHandler(fileHandler)
    logger.info('Added log file handler for file: ' + fn)

continueOnError = False
if config['DEFAULT']['continueOnError'] == 'Y' or config['DEFAULT']['continueOnError'] == 'y':
    continueOnError = True
logger.info('continueOnError = ' + str(continueOnError))

hcmApi.continueOnError = continueOnError
hcmApi.logger = logger
idcsApi.continueOnError = continueOnError
idcsApi.logger = logger

continueOnError = False
if config['DEFAULT']['continueOnError'] == 'Y' or config['DEFAULT']['continueOnError'] == 'y':
    continueOnError = True

logger.debug('continueOnError = ' + str(continueOnError))

# HCM config 1st

hcm = {}
hcm['resourcePaths'] = json.loads(config['HCM']['restResourcePaths'])

hcm['host'] = config['HCM']['host']
hcm['username'] = config['HCM']['username']
hcm['password'] = ''

logger.debug('')
logger.debug('hcm configuration info:')
logger.debug('\n'+ pp.pformat(hcm))

# IDCS config 2nd

idcs = {}

idcs['host'] = config['IDCS']['host']
idcs['username'] = config['IDCS']['username']
idcs['resourcePaths'] = json.loads( config['IDCS']['restResourcePaths'] )

idcs['clientID'] = ''
idcs['clientSecret'] = ''
idcs['password'] = ''

logger.debug('')
logger.debug('idcs configuration:')
logger.debug('\n'+ pp.pformat(idcs))
logger.debug('')

# check passwords
if hcm['password'] is None or len(hcm['password'].strip()) == 0:
    hcm['password'] = getpass.getpass(prompt='Please enter HCM password for user ' + hcm['username'] + ' : ')

if idcs['clientID'] is None or len(idcs['clientID'].strip()) == 0:
    idcs['clientID'] = getpass.getpass(prompt='Please enter IDCS client ID : ')
if idcs['clientSecret'] is None or len(idcs['clientSecret'].strip()) == 0:
    idcs['clientSecret'] = getpass.getpass(prompt='Please enter IDCS client secret : ')

if idcs['password'] is None or len(idcs['password'].strip()) == 0:
    idcs['password'] = getpass.getpass(prompt='Please enter IDCS password for user ' + idcs['username'] + ' : ')

taskNames = []
for itemSection in config.items():
    sectionName = itemSection[0]
    section = itemSection[1]
    if sectionName.startswith('TASK'):
        taskNames.append(sectionName)

logger.info('Will perform tasks: ')
logger.info('\n' + pp.pformat(taskNames))

idcsApi.initAccessToken(idcs)

for taskName in taskNames:
    taskType = config[taskName]['taskType']
    if taskType == 'sync':
        sync(hcm, idcs, config[taskName])
    elif taskType == 'deleteUsers':
        deleteUsers(idcs, config[taskName])
    elif taskType == 'revokeGrants':
        revoke(idcs, config[taskName])
    elif taskType == 'grantUsersAppRole':
        grant(idcs, config[taskName])
    elif taskType == 'addUsersToGroups':
        addToGroups(idcs, config[taskName])
    elif taskType == 'removeUsersFromGroups':
        removeFromGroups(idcs, config[taskName])

logger.info('Done!')


