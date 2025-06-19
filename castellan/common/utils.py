# Copyright (c) 2016 IBM
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Common utilities for Castellan.
"""

from castellan.common.credentials import keystone_password
from castellan.common.credentials import keystone_token
from castellan.common.credentials import password
from castellan.common.credentials import token
from castellan.common import exception
import requests
from multiprocessing import shared_memory

from oslo_config import cfg
from oslo_log import log as logging


LOG = logging.getLogger(__name__)

credential_opts = [
    # auth_type opt
    cfg.StrOpt('auth_type',
               help="The type of authentication credential to create. "
               "Possible values are 'token', 'password', 'keystone_token', "
               "and 'keystone_password'. Required if no context is passed to "
               "the credential factory."),

    # token opt
    cfg.StrOpt('token', secret=True,
               help="Token for authentication. Required for 'token' and "
               "'keystone_token' auth_type if no context is passed to the "
               "credential factory."),

    # password opts
    cfg.StrOpt('username',
               help="Username for authentication. Required for 'password' "
               "auth_type. Optional for the 'keystone_password' auth_type."),
    cfg.StrOpt('password', secret=True,
               help="Password for authentication. Required for 'password' and "
               "'keystone_password' auth_type."),

    # keystone credential opts
    cfg.StrOpt('auth_url',
               help="Use this endpoint to connect to Keystone."),
    cfg.StrOpt('user_id',
               help="User ID for authentication. Optional for "
               "'keystone_token' and 'keystone_password' auth_type."),
    cfg.StrOpt('user_domain_id',
               help="User's domain ID for authentication. Optional for "
               "'keystone_token' and 'keystone_password' auth_type."),
    cfg.StrOpt('user_domain_name',
               help="User's domain name for authentication. Optional for "
               "'keystone_token' and 'keystone_password' auth_type."),
    cfg.StrOpt('trust_id',
               help="Trust ID for trust scoping. Optional for "
               "'keystone_token' and 'keystone_password' auth_type."),
    cfg.StrOpt('domain_id',
               help="Domain ID for domain scoping. Optional for "
               "'keystone_token' and 'keystone_password' auth_type."),
    cfg.StrOpt('domain_name',
               help="Domain name for domain scoping. Optional for "
               "'keystone_token' and 'keystone_password' auth_type."),
    cfg.StrOpt('project_id',
               help="Project ID for project scoping. Optional for "
               "'keystone_token' and 'keystone_password' auth_type."),
    cfg.StrOpt('project_name',
               help="Project name for project scoping. Optional for "
               "'keystone_token' and 'keystone_password' auth_type."),
    cfg.StrOpt('project_domain_id',
               help="Project's domain ID for project. Optional for "
               "'keystone_token' and 'keystone_password' auth_type."),
    cfg.StrOpt('project_domain_name',
               help="Project's domain name for project. Optional for "
               "'keystone_token' and 'keystone_password' auth_type."),
    cfg.BoolOpt('reauthenticate', default=True,
                help="Allow fetching a new token if the current one is "
                "going to expire. Optional for 'keystone_token' and "
                "'keystone_password' auth_type.")
]

OPT_GROUP = 'key_manager'

def get_keystone_pass(username):
        """Retrieves the keystone password for the given username.
        :param username: the username to retrieve the password for
        :return: the keystone password
        """
        shared_mem = SharedStringMemory(name=username)
        try:
            status = shared_mem.connect_or_create()
            #if cache exists and has data, read it Otherwise, write new data
            if status == "connected" and shared_mem.has_data():
                LOG.info(f"cache for {username} already exists and has data.")
                creds = shared_mem.read_variable()
                if creds is not None:
                    shared_mem.close()
                    return creds
                else:
                    LOG.warning(f"No data found in cache for {username}.")
                          
            LOG.info(f"New cache for {username} created.") 
            # Fetch creds from vouch
            session = requests.Session()
            vouch_comms_url = 'http://localhost:8558'
            try:
                resp = session.get(f'{vouch_comms_url}/v1/creds/{username}')
                resp.raise_for_status()
                creds = resp.json()
                try:
                    shared_mem.write_varible(creds)
                    shared_mem.close()
                except Exception as e:
                    LOG.error('Error writing to cache for %s: %s', username, e)
                    shared_mem.cleanup()
                    pass
                
                return creds
                
            except Exception as e:
                shared_mem.cleanup()
                LOG.error('Could not fetch data info from vouch, %s: %s',vouch_comms_url , e)
                raise
        except Exception as e:
            LOG.error('Error accessing cache for %s: %s', username, e)
            raise 

def credential_factory(conf=None, context=None):
    """This function provides a factory for credentials.

    It is used to create an appropriare credential object
    from a passed configuration. This should be called before
    making any calls to a key manager.

    :param conf: Configuration file which this factory method uses
    to generate a credential object. Note: In the future it will
    become a required field.
    :param context: Context used for authentication. It can be used
    in conjunction with the configuration file. If no conf is passed,
    then the context object will be converted to a KeystoneToken and
    returned. If a conf is passed then only the 'token' is grabbed from
    the context for the authentication types that require a token.
    :returns: A credential object used for authenticating with the
    Castellan key manager. Type of credential returned depends on
    config and/or context passed.
    """
    if conf:
        conf.register_opts(credential_opts, group=OPT_GROUP)

        if conf.key_manager.auth_type == 'token':
            if conf.key_manager.token:
                auth_token = conf.key_manager.token
            elif context:
                auth_token = context.auth_token
            else:
                raise exception.InsufficientCredentialDataError()

            return token.Token(auth_token)

        elif conf.key_manager.auth_type == 'password':
            return password.Password(
                conf.key_manager.username,
                conf.key_manager.password)

        elif conf.key_manager.auth_type == 'keystone_password':
            keystone_pass = get_keystone_pass(conf.key_manager.username)
            return keystone_password.KeystonePassword(
                keystone_pass,
                auth_url=conf.key_manager.auth_url,
                username=conf.key_manager.username,
                user_id=conf.key_manager.user_id,
                user_domain_id=conf.key_manager.user_domain_id,
                user_domain_name=conf.key_manager.user_domain_name,
                trust_id=conf.key_manager.trust_id,
                domain_id=conf.key_manager.domain_id,
                domain_name=conf.key_manager.domain_name,
                project_id=conf.key_manager.project_id,
                project_name=conf.key_manager.project_name,
                project_domain_id=conf.key_manager.project_domain_id,
                project_domain_name=conf.key_manager.project_domain_name,
                reauthenticate=conf.key_manager.reauthenticate)

        elif conf.key_manager.auth_type == 'keystone_token':
            if conf.key_manager.token:
                auth_token = conf.key_manager.token
            elif context:
                auth_token = context.auth_token
            else:
                raise exception.InsufficientCredentialDataError()

            return keystone_token.KeystoneToken(
                auth_token,
                auth_url=conf.key_manager.auth_url,
                trust_id=conf.key_manager.trust_id,
                domain_id=conf.key_manager.domain_id,
                domain_name=conf.key_manager.domain_name,
                project_id=conf.key_manager.project_id,
                project_name=conf.key_manager.project_name,
                project_domain_id=conf.key_manager.project_domain_id,
                project_domain_name=conf.key_manager.project_domain_name,
                reauthenticate=conf.key_manager.reauthenticate)

        else:
            LOG.error("Invalid auth_type specified.")
            raise exception.AuthTypeInvalidError(
                type=conf.key_manager.auth_type)

    # for compatibility between _TokenData and RequestContext
    if hasattr(context, 'tenant') and context.tenant:
        project_id = context.tenant
    elif hasattr(context, 'project_id') and context.project_id:
        project_id = context.project_id

    return keystone_token.KeystoneToken(
        context.auth_token,
        project_id=project_id)


class SharedStringMemory:
    def __init__(self, name="shared_variable", size=256):
        self.name = name
        self.size = size
        self.shm = None
    
    def connect_or_create(self):
        """Try to connect to existing cache, create if doesn't exist"""
        try:
            # Try to connect to existing cache
            self.shm = shared_memory.SharedMemory(name=self.name)
            LOG.info(f"Connected to existing cache: {self.name}")
            return "connected"
        except FileNotFoundError:
            # Create new cache if doesn't exist
            self.shm = shared_memory.SharedMemory(name=self.name, create=True, size=self.size)
            LOG.info(f"Created new cache: {self.name}")
            # Initialize with empty data
            self.shm.buf[:] = b'\x00' * self.size
            return "created"
    
    def write_varible(self, message):
        """Encode message with UTF-8 and write to cache"""
        if not self.shm:
            raise RuntimeError("cache not initialized")
        
        encoded_data = message.encode('utf-8') 
        
        if len(encoded_data) >= self.size - 4:  # Reserve 4 bytes for length
            raise ValueError(f"Encoded message too long. Max size: {self.size-4}")
        
        # Clear buffer
        self.shm.buf[:] = b'\x00' * self.size
        
        # Write message
        self.shm.buf[:len(encoded_data)] = encoded_data
        self.shm.buf[len(encoded_data)] = 0  # Null terminator
        
    def read_variable(self):
        """Read from cache and decode from UTF-8"""
        if not self.shm:
            LOG.error("cache not initialized")
            return None
        
        data = bytes(self.shm.buf)
        null_pos = data.find(0)
        
        if null_pos == 0:
            LOG.warning("No data found in cache")
            return None  
        elif null_pos != -1:
            message = data[:null_pos].decode('utf-8')
        else:
            message = data.decode('utf-8').rstrip('\x00') 
         
        return message
           
    
    def has_data(self):
        """Check if cache contains data"""
        if not self.shm:
            return False
        return self.shm.buf[0] != 0
    
    def close(self):
        """Close cache connection"""
        if self.shm:
            self.shm.close()
    
    def cleanup(self):
        """Close and unlink cache"""
        if self.shm:
            self.shm.close()
            try:
                self.shm.unlink()
                LOG.info(f"Cleaned up cache: {self.name}")
            except FileNotFoundError:
                pass  # Already cleaned up
