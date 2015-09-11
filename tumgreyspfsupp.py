#!/usr/bin/env python
#
# Copyright (c) 2004-2007, Sean Reifschneider, tummy.com, ltd.
# All Rights Reserved.

import os
import sys
import string
import re
import urllib
import stat

import syslog






#  default values
defaultConfigFilename = '/var/local/lib/tumgreyspf/config/tumgreyspf.conf'
defaultConfigData = {
    'debugLevel': 0,
    'defaultSeedOnly': 0,
    'defaultAllowTime': 600,
    'configPath': 'file:///var/local/lib/tumgreyspf/config',
    'greylistDir': '/var/local/lib/tumgreyspf/data',
    'blackholeDir': '/var/local/lib/tumgreyspf/blackhole',
    'spfqueryPath': '/usr/local/lib/tumgreyspf/spfquery',
    'ignoreLastByte': 0,
}


#################################
class ConfigException(Exception):
    """
    Exception raised when there's a configuration file error.
    """
    pass


#################################
def load_config_file(file_name, values):
    """
    Loads and parses a configuration file.

    :param file_name: The config file to load and parse.
    :param values: A dictionary of default config values.
    :return: Nothing. Values is modified in place.
    :raises: ConfigException when there is an error in the config file.
    """

    if not os.path.exists(file_name):
        return

    try:
        execfile(file_name, {}, values)
    except Exception:
        import traceback
        error_type, value, tb = sys.exc_info()
        raise ConfigException('Error reading config file "%s": %s' % (
            file_name, sys.exc_info()[1]))

    return ()


####################################################################
def process_config_file(filename=None, config=None, use_syslog=1,
                        use_stderr=0):
    """
    Load the specified config file, exit and log errors if it fails, otherwise
    return a config dictionary.

    :param filename: The config file to load and process. If None,
        tumgreyspfsupp.defaultConfigFilename is used.
    :param config: A dictionary of config data; the loaded values from the
        file are added to this dictionary. If None,
        tumgreyspfsupp.defaultConfigData is used.
    :param use_syslog: if 1, errors will be written to the syslog.
    :param use_stderr:  if 1, errors will be written to stderr.
    :return: The config dictionary.
    """

    import tumgreyspfsupp

    if config is None:
        config = tumgreyspfsupp.defaultConfigData
    if filename is None:
        filename = tumgreyspfsupp.defaultConfigFilename

    try:
        load_config_file(filename, config)
    except Exception, e:
        if use_syslog:
            syslog.syslog(e.args[0])
        if use_stderr:
            sys.stderr.write('%s\n' % e.args[0])
        sys.exit(1)

    return config


#################
class ExceptHook:
    def __init__(self, use_syslog=1, use_stderr=0):
        self.useSyslog = use_syslog
        self.useStderr = use_stderr

    def __call__(self, etype, evalue, etb):
        import traceback
        import string

        tb = traceback.format_exception(*(etype, evalue, etb))
        tb = map(string.rstrip, tb)
        tb = string.join(tb, '\n')
        for line in string.split(tb, '\n'):
            if self.useSyslog:
                syslog.syslog(line)
            if self.useStderr:
                sys.stderr.write(line + '\n')


####################
def set_except_hook():
    sys.excepthook = ExceptHook(use_syslog=1, use_stderr=1)


####################
def quote_address(s):
    """
    Quotes an address so that it's safe to store in the file-system.
    Address can either be a domain name, or local part.

    :param s: The address to add quotes to.
    :return: The quoted address.
    """

    s = urllib.quote(s, '@_-+')
    if len(s) > 0 and s[0] == '.':
        s = '%2e' + s[1:]

    return s


######################
def unquote_address(s):
    """
    Removes the quotes from an address. Alias function for urllib.unquote(s)

    :param s: The quoted address.
    :return: The unquoted address.
    """

    return urllib.unquote(s)


###############################################################
commentRx = re.compile(r'^(.*)#.*$')


def read_config_file(path, config_data=None, config_global={}):
    """
    Reads a configuration file from the given path, and merges it with the
    data in the config_data variable. Returns a dictionary of name/value
    pairs.

    :param path: The path to the configuration file.
    :param config_data: The already specified configuration settings. If
        None, an empty dictionary will be used.
    :param global_config: The global configuration settings (used to
        determine the debug level).
    :return: A dictionary with name/value of the config_data, augmented
        with the parsed config entries from the file.
    """

    debug_level = config_global.get('debugLevel', 0)
    if debug_level >= 3:
        syslog.syslog('readConfigFile: Loading "%s"' % path)

    if config_data is None:
        config_data = {}

    name_conversion = {
        'SPFSEEDONLY': int,
        'GREYLISTTIME': int,
        'CHECKERS': str,
        'OTHERCONFIGS': str,
        'GREYLISTEXPIREDAYS': float,
    }

    #  check to see if it's a file
    try:
        mode = os.stat(path)[0]
    except OSError, e:
        syslog.syslog('ERROR stating "%s": %s' % (path, e.strerror))
        return config_data
    if not stat.S_ISREG(mode):
        syslog.syslog(
            'ERROR: is not a file: "%s", mode=%s' % (path, oct(mode)))
        return config_data

    # load file
    fp = open(path, 'r')
    while 1:
        line = fp.readline()
        if not line:
            break

        #  parse line
        line = string.strip(string.split(line, '#', 1)[0])
        if not line:
            continue

        data = map(string.strip, string.split(line, '=', 1))
        if len(data) != 2:
            syslog.syslog('ERROR parsing line "%s" from file "%s"'
                          % (line, path))
            continue
        name, value = data

        #  check validity of name
        conversion = name_conversion.get(name)
        if conversion is None:
            syslog.syslog(
                'ERROR: Unknown name "%s" in file "%s"' % (name, path))
            continue

        if debug_level >= 4:
            syslog.syslog('readConfigFile: Found entry "%s=%s"' % (name,
                                                                   value))
        config_data[name] = conversion(value)
    fp.close()

    return config_data


####################################################
def lookup_config(config_path, msg_data, config_global):
    """
    Tries to load a configuration based on the given path and msg_data.

    :param config_path: The path were there could be a configuration file.
    :param msg_data: Data from the message (sender, recipient,
        client_address, ...)
    :param config_global: The global configuration. Used for the debug
        statements and setting default values if no configuration could be
        loaded.
    :return: A dictionary with name/value pairs.
    """

    debug_level = config_global.get('debugLevel', 0)

    #  set up default config
    config_data = {
        'SPFSEEDONLY': config_global.get('defaultSeedOnly'),
        'GREYLISTTIME': config_global.get('defaultAllowTime'),
        'CHECKGREYLIST': 1,
        'CHECKSPF': 1,
        'OTHERCONFIGS': 'envelope_sender,envelope_recipient',
    }

    #  load directory-based config information
    if config_path[:8] == 'file:///':
        if debug_level >= 3:
            syslog.syslog('lookupConfig: Starting file lookup from "%s"'
                          % config_path)
        base_path = config_path[7:]
        config_data = {}

        #  load default config
        path = os.path.join(base_path, '__default__')
        if os.path.exists(path):
            if debug_level >= 3:
                syslog.syslog(
                    'lookupConfig: Loading default config: "%s"' % path)
            config_data = read_config_file(path, config_data, config_global)
        else:
            syslog.syslog(('lookupConfig: No default config found in "%s", '
                           'this is probably an install problem.') % path)

        # load other configs from OTHERCONFIGS
        configs_already_loaded = {}
        did_load = 1
        while did_load:
            did_load = 0
            other_configs = string.split(config_data.get('OTHERCONFIGS', ''),
                                         ',')
            if not other_configs or other_configs == ['']:
                break
            if debug_level >= 3:
                syslog.syslog('lookupConfig: Starting load of configs: "%s"'
                              % str(other_configs))

            # SENDER/RECIPIENT
            for cfg_type in other_configs:
                cfg_type = string.strip(cfg_type)

                #  skip if already loaded
                if configs_already_loaded.get(cfg_type) is not None:
                    continue
                configs_already_loaded[cfg_type] = 1
                did_load = 1
                if debug_level >= 3:
                    syslog.syslog(
                        'lookupConfig: Trying config "%s"' % cfg_type)

                # SENDER/RECIPIENT
                if cfg_type == 'envelope_sender' or cfg_type == \
                        'envelope_recipient':
                    #  get address
                    if cfg_type == 'envelope_sender':
                        address = msg_data.get('sender')
                    else:
                        address = msg_data.get('recipient')
                    if not address:
                        if debug_level >= 2:
                            syslog.syslog(
                                'lookupConfig: Could not find %s' % cfg_type)
                        continue

                    # split address into domain and local
                    data = string.split(address, '@', 1)
                    if len(data) != 2:
                        if debug_level >= 2:
                            syslog.syslog(
                                'lookupConfig: Could not find %s address '
                                'from "%s", skipping' % (cfg_type, address))
                        continue
                    local = quote_address(data[0])
                    domain = quote_address(data[1])

                    #  load configs
                    path = os.path.join(base_path, cfg_type)
                    domain_path = os.path.join(path, domain, '__default__')
                    local_path = os.path.join(path, domain, local)
                    for name in (domain_path, local_path):
                        if debug_level >= 3:
                            syslog.syslog(
                                'lookupConfig: Trying file "%s"' % name)
                        if os.path.exists(name):
                            config_data = read_config_file(name,
                                                           config_data,
                                                           config_global)

                # CLIENT IP ADDRESS
                elif cfg_type == 'client_address':
                    ip = msg_data.get('client_address')
                    if not ip:
                        if debug_level >= 2:
                            syslog.syslog(
                                'lookupConfig: Could not find client '
                                'address')
                    else:
                        path = base_path
                        for name in ['client_address'] \
                                + list(string.split(ip, '.')):
                            path = os.path.join(path, name)
                            default_path = os.path.join(path, '__default__')
                            if debug_level >= 3:
                                syslog.syslog('lookupConfig: Trying file "%s"'
                                              % default_path)
                            if os.path.exists(default_path):
                                config_data = read_config_file(default_path,
                                                               config_data,
                                                               config_global)
                        if debug_level >= 3:
                            syslog.syslog(
                                'lookupConfig: Trying file "%s"' % path)
                        if os.path.exists(path):
                            config_data = read_config_file(path,
                                                           config_data,
                                                           config_global)

                # unknown configuration type
                else:
                    syslog.syslog('ERROR: Unknown configuration type: "%s"'
                                  % cfg_type)

    # unknown config path
    else:
        syslog.syslog('ERROR: Unknown path type in: "%s", using defaults'
                      % msg_data)

    # return results
    return config_data
