#!/usr/bin/env python3

import argparse
import json
import pathlib
import shlex
import subprocess

CONFIG = {
        "default_key_alg": "EC -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve",
        "out_path": "./certs",
        "cert_file": "cert.pem",
        "key_file": "key.pem",
        "services": [],
}


def openssl(*args):
    """ Run the OpenSSL command

    Args:
        args -- A list of arguments.
    """
    cmdline = ['openssl']
    for arg in args:
        cmdline += shlex.split(arg)
    subprocess.check_call(cmdline)


class Service(object):

    """A Service object hold the name and certificate for a service"""

    def __init__(self, name, key_alg, out_path, confidant_names):
        self.name = name
        self.path = mkdir(out_path.joinpath(name))
        self.key_file = None
        self.key_alg = key_alg
        self.cert_file = None
        self.formats = []
        self.create_key()
        self.confidants = confidant_names
        self.confidat_file = None

    def create_key(self):
        """ Create a private key with the given algorithmen

        Args:
            self --

        Returns:
            the path to the newly created private key file as a string.
        """
        self.key_file = str(self.path.joinpath('{}.key.pem'.format(self.name)))
        openssl('genpkey -outform PEM -algorithm', self.key_alg, '-out', shlex.quote(self.key_file))
        return self.key_file

    def create_cert(self, subject_str):
        """ Create the certificate for the service

        Args:
            self --
            subject_str -- the subject string for the certificate

        Retruns:
            the path to the newly created certificate as a string.
        """
        self.cert_file = str(self.path.joinpath('{}.cer.pem'.format(self.name)))
        openssl('req -new -days 365 -nodes -x509 -outform PEM -subj', shlex.quote(subject_str),
                '-out', shlex.quote(self.cert_file),
                '-key', shlex.quote(self.key_file))
        return self.cert_file

    def create_confidants(self, service_dict):
        filename = '{}.confidants.pem'.format(self.name)
        services_confidants = self.path.joinpath(filename)
        with services_confidants.open('w') as confidants_file:
            for confidant in self.confidants:
                with open(service_dict[confidant].cert_file) as confidant_cert:
                    for line in confidant_cert:
                        confidants_file.write(line)
        self.confidat_file = str(services_confidants)

    def create_pkcs12_keystore(self):
        filename = '{}.keystore.p12'.format(self.name)
        openssl('pkcs12 -export',
                '-in', self.cert_file,
                '-inkey', self.key_file,
                '-name', self.name,
                '-out', filename)

    def create_pkcs12_truststore(self):
        filename = '{}.keystore.p12'.format(self.name)
        openssl('pkcs12 -export',
                '-in', self.cert_file,
                '-nokeys'
                '-name', self.name,
                '-out', filename)


def mkdir(path):
    """ Create a new directory with the path

    Args:
        path -- the path to the new directory
    Return:
        the path object
    """
    try:
        path.mkdir(mode=0o700)
    except OSError:
        pass
        # ignore the error since it is already there
    return path


def read_config(config, json_data_file):
    """ Read the config for bob

    Args:
        config -- the configuration object whith the default values
        json_data_file -- the json file which holds the configuration inforation
    Returns:
        the updated configuration
    """
    with json_data_file:
        loaded_conf = json.load(json_data_file)
        config.update(loaded_conf)
        return config


def parse_args():
    """ Prarse the arguments """
    parser = argparse.ArgumentParser(description='Bob the certificate builder.')
    parser.add_argument('--config', default='./config/cert_conf.json',
                        type=argparse.FileType('r'),
                        help='configuration file for the creation of certificates')
    return parser.parse_args()


def create_credentials(out_path, services, default_key_alg):
    """ Create the creadentials for all services

    Args:
        out_path -- the path where the new certificates should be stored
        service -- a list of the services
        default_key_alg -- the default algorithmen for which keys should be created
    """
    service_dict = {}

    for s in services:
        service_name = s['name']
        subject_str = s['subject_str']
        key_alg = s.get('key_alg', default_key_alg)
        confidant_names = s['confidants']
        service = Service(service_name, key_alg, out_path, confidant_names)
        service.create_cert(subject_str)

        service_dict[service.name] = service

    for service in service_dict.values():
        service.create_confidants(service_dict)


def main():
    """ Main function """
    args = parse_args()
    config = read_config(CONFIG, args.config)
    out_path = mkdir(pathlib.Path(config['out_path']))

    create_credentials(out_path, config['services'], config['default_key_alg'])


if __name__ == '__main__':
    main()
