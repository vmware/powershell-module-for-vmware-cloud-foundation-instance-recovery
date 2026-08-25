# Copyright 2020 VMware, Inc.  All rights reserved. -- VMware Confidential

"""Service to support refresh SSH keys. This operation checks whether the SSH keys in known_hosts file are valid. If
not, gets the latest keys from the corresponding components and updates in known_hosts file.

"""
import argparse
import base64
import os
import traceback
import json
import socket
import hashlib
import subprocess
import requests
import logging
import threading
from six.moves import input

GREEN_PREFIX = '\x1b[1;32m'
COLOR_POSTFIX = '\x1b[0m'
LOG_FILENAME = os.getcwd() + '/refresh-ssh-keys.log'
logging.basicConfig(filename=LOG_FILENAME, level=logging.DEBUG)
SSH_DEFAULT_PORT = 22
GET_SSH_KEY_CMD = "ssh-keyscan -t {} {} | awk 'NF==3 {{print $3}}'"
GET_SSH_KEY_WITH_PORT_CMD = "ssh-keyscan -t {} -p {} {} | awk 'NF==3 {{print $3}}'"
GLCM_SDDC_KNOWN_HOSTS_REST = 'http://localhost/appliancemanager/ssh/knownHosts'


class RefreshSSHKeys:
    """
    This class implements methods to support refresh SSH keys
    """

    def __init__(self):
        self.log = logging.getLogger('RefreshSSHKeys')

    def execute_cmd_locally(self, cmd, log_stdout=True, mask_password=None,
                            timeout=-1):
        masked_cmd = cmd
        if mask_password:
            masked_cmd = str(masked_cmd).replace(mask_password,
                                                 '*******')
        self.log.info('Execute cmd: %s' % masked_cmd)
        ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, close_fds=True)
        timer = None
        if timeout > 0:
            self.log.debug('Command timeout: %s' % timeout)
            # Kill the process if it exceeds given timeout
            # Run it only for non-background commands
            timer = threading.Timer(timeout, ps.kill)
            timer.start()
        out = ''
        err = ''
        try:
            while True:
                line = ps.stdout.readline()
                if not line:
                    break
                # line = line.strip(os.linesep)
                out += line.decode()
                if log_stdout:
                    self.log.info(line)
            while True:
                line = ps.stderr.readline()
                if not line:
                    break
                # line = line.strip(os.linesep)
                err += line.decode()
                self.log.error(line)
            rc = ps.wait()
        finally:
            if timer:
                timer.cancel()

        # Add timeout message to err if occurs
        if timeout and rc == -9:
            _error_msg = 'Command {} did not complete even after waiting for ' \
                         '{} seconds'.format(cmd, timeout)
            err += ' ; {}'.format(_error_msg)
            self.log.error('Std Error : {}'.format(err))
        self.log.info('RC: %s' % rc)
        return rc, out, err

    def getBase64SHA256(self, b64pubkey):
        if b64pubkey is None:
            raise Exception('Input to hashFunction can not be null')
        sha256 = hashlib.sha256()
        sha256.update(base64.b64decode(b64pubkey))
        b64sha256fingerprint = base64.b64encode(sha256.digest()).decode("utf-8")
        return 'SHA256:{}'.format(b64sha256fingerprint[:len(b64sha256fingerprint)-1])

    def getRDNS(self, host):
        host_details = socket.gethostbyaddr(host)
        # example host_details: ('esxi-1.vrack.vsphere.local', [], ['10.0.0.100'])
        if host in host_details[2]:
            return host_details[0]
        else:
            return host_details[2][0]

    def getAllSSHKeys(self):
        self.log.info('Invoking {} API to get existing SSH keys'.format(GLCM_SDDC_KNOWN_HOSTS_REST))
        response = requests.get(GLCM_SDDC_KNOWN_HOSTS_REST)
        # If block will be executed if the status code was not between 200 and 400
        if response.status_code != 200 or not response:
            self.log.error('Failed to get SSH keys: {}'.format(response))
            print('Failed to get SSH keys: {}'.format(response))
            exit(1)
        known_hosts = json.loads(response.text)
        self.log.info('There are {} SSH keys in known_hosts'.format(len(known_hosts["knownHosts"])))
        return known_hosts

    def toLabels(self, value):
        """Lowercased matchable labels for a host value: itself, plus its short name if it
        looks like an FQDN (e.g. 'esx01.domain.local' -> {'esx01.domain.local', 'esx01'})."""
        if not value:
            return set()
        value = value.strip().lower()
        labels = {value}
        if self.isFqdn(value):
            short = value.split('.')[0]
            if short:
                labels.add(short)
        return labels

    def isFqdn(self, address):
        try:
            socket.inet_aton(address)
            return False
        except Exception as e:
            self.log.info('{} is a FQDN'.format(address))
            return True

    def getFingerprint(self, host, key_type, port=None):
        self.log.info('Fetching current {} key of {}'.format(key_type, host))
        if port is None or port == SSH_DEFAULT_PORT:
            cmd_to_execute = GET_SSH_KEY_CMD.format(key_type, host)
        else:
            cmd_to_execute = GET_SSH_KEY_WITH_PORT_CMD.format(key_type, port, host)
        rc, out, err = self.execute_cmd_locally(cmd_to_execute)
        if not out:
            fqdn = socket.getfqdn(host)  # It will return fqdn even if the input is fqdn
            self.log.error('Failed to fetch {} key for {}: {}'.format(key_type, fqdn, err))
            if self.isFqdn(host) and not err:  # Observed that when SSH is disabled, not seeing any error message.
                print(
                    '\nFailed to fetch {} key for {}. Make sure SSH is enabled. Retry the '
                    'operation after '
                    'remediating the problem: {}'.format(key_type, fqdn, err))
            else:
                print(
                    '\nFailed to fetch {} key for {}. Retry the operation after remediating the problem: {}'.format(
                        key_type, fqdn, err))
        lines = out.strip().splitlines()
        return lines[-1].strip() if lines else ''

    # flake8: noqa: C901
    def getAndConfirmSSHKeyUpdate(self, known_hosts, targets=None):
        fetch_keys_failed_comps = list()
        update_comps = list()
        not_update_comps = list()
        skipped_comps = list()
        for knownhost_entry in known_hosts["knownHosts"]:
            host = knownhost_entry["host"]
            key_type = knownhost_entry["keyType"]
            port = knownhost_entry.get("port")
            fqdn = socket.getfqdn(host)

            if targets and not (targets & (self.toLabels(host) | self.toLabels(fqdn))):
                self.log.info('Skipping {} (not in the requested target list)'.format(host))
                skipped_comps.append(fqdn)
                continue

            try:
                current_fingerprint = self.getFingerprint(host, key_type, port)
                if not current_fingerprint:
                    fetch_keys_failed_comps.append(fqdn)
                    continue

                if current_fingerprint == knownhost_entry["key"]:
                    self.log.info('SSH key is matched for {}'.format(host))
                    continue

                self.log.info('SSH key is not matched for {}'.format(host))
                sha256_hash = self.getBase64SHA256(current_fingerprint)
                rdns = self.getRDNS(host)
                print('\nSSH key for component with ip address: {} and hostname: {} does not match.'.format(host, rdns))
                print('New fingerprint for {} key is {}.'.format(key_type, sha256_hash))
                data = input('Are you sure you want to update {} key (yes/no)? '.format(key_type))
                while 1:
                    if 'Y' == data.upper() or 'YES' == data.upper():
                        self.log.info('User has confirmed to update SSH key for {}'.format(host))
                        knownhost_entry["key"] = current_fingerprint
                        update_comps.append(fqdn)
                        break
                    elif 'N' == data.upper() or 'NO' == data.upper():
                        self.log.info('User is disagreed to update SSH key for {}'.format(host))
                        not_update_comps.append(fqdn)
                        break
                    else:
                        data = input('Please type \'yes\' or \'no\': ')
            except Exception as e:
                self.log.error(traceback.format_exc())
                self.log.error('Failed to fetch SSH key for {}: {}'.format(fqdn, e))
                print('\nFailed to fetch {} key for {}. Retry the operation after remediating the problem: {}'.format(
                    key_type, fqdn, e))

        if skipped_comps:
            print('\nSkipped (outside requested target list): {}'.format(skipped_comps))
        if fetch_keys_failed_comps:
            print('\nFetch SSH key was failed for {}'.format(fetch_keys_failed_comps))
        if not_update_comps:
            print('\nSSH keys will not be updated for {}'.format(not_update_comps))

        if len(update_comps) == 0:
            self.log.info('No components are selected or not required for SSH key update')
            print('\nNo components are selected or not required for SSH key update. Exiting.')
            exit(0)

    def updateSSHKeys(self, known_hosts):
        self.log.info('Invoking {} API to update SSH keys'.format(GLCM_SDDC_KNOWN_HOSTS_REST))
        headers = {'Content-Type': 'application/json'}
        data = json.dumps(known_hosts)
        response = requests.post(GLCM_SDDC_KNOWN_HOSTS_REST, data=data, headers=headers)
        if response.status_code != 200 or not response:
            self.log.error('Failed to the refresh SSH keys: {}'.format(response))
            print('\nFailed to refresh the SSH keys: {}'.format(response))
            exit(1)

    def execute(self):
        """
        Execute refresh SSH keys operations
        """
        parser = argparse.ArgumentParser()
        parser.add_argument('--targets', default=None,
                            help='Comma-separated list of hostnames, IPs, FQDNs, or short names '
                                 '(e.g. ESXi hosts or a specific appliance) to restrict the '
                                 'refresh to. Matches against each known_hosts entry\'s host '
                                 'value and its resolved FQDN. Omit to process every known_hosts '
                                 'entry, matching the original unfiltered behavior.')
        args = parser.parse_args()
        targets = None
        if args.targets:
            targets = set()
            for target in args.targets.split(','):
                targets |= self.toLabels(target)

        try:
            print('Starting {}Refresh SSH keys{} operation..'.format(GREEN_PREFIX, COLOR_POSTFIX))
            print('Logs: {}'.format(LOG_FILENAME))
            known_hosts = self.getAllSSHKeys()
            self.getAndConfirmSSHKeyUpdate(known_hosts, targets)
            self.updateSSHKeys(known_hosts)
            print('\nRefreshed SSH keys successfully!!!')
        except Exception as e:
            self.log.error(traceback.format_exc())
            self.log.error(e)
            self.log.error('Refresh SSH keys operation failed: {}'.format(e))
            print('\nRefresh SSH keys operation failed.')
        finally:
            self.log.info('SSH keys refresh completed')


if __name__ == '__main__':
    refreshSSHKeys = RefreshSSHKeys()
    refreshSSHKeys.execute()
