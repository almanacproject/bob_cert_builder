#!/usr/bin/env python3

import json
import os
import pathlib
import random
import shlex
import string
import subprocess


def openssl(cmd, *args, **kwargs):
    openssl_with_fds(cmd, (), *args, **kwargs)


def openssl_with_fds(cmd, pass_fds, *args, **kwargs):
    """ Run the OpenSSL command

    Args:
        args -- A list of arguments.
    """
    execute('openssl', cmd, pass_fds, args, kwargs)


def keytool(cmd, *args, **kwargs):
    execute('keytool', cmd, (), args, kwargs)


def execute(tool, cmd, pass_fds, args, kwargs):
    quoted_args = (shlex.quote(arg) for arg in args)
    qouted_kwargs = {key: shlex.quote(arg) for key, arg in kwargs.items()}

    qouted_command = cmd.format(*quoted_args, **qouted_kwargs)

    cmdline = [tool] + shlex.split(qouted_command)
    # print(' '.join(cmdline))
    proc = subprocess.Popen(cmdline, pass_fds=pass_fds, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc.wait()
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, ' '.join(cmdline))


class password_pipe(object):
    def __init__(self, password):
        self.password = password
        self.__write_fd = None
        self.__read_fd = None

    def __enter__(self):
        self.__read_fd, self.__write_fd = os.pipe()
        os.set_inheritable(self.__read_fd, True)
        os.write(self.__write_fd, self.password.encode())
        os.write(self.__write_fd, '\n'.encode())
        return self.__read_fd

    def __exit__(self, type, value, traceback):
        os.close(self.__write_fd)
        os.close(self.__read_fd)


class ConvertMixin(object):

    def convert_to(self, format):
        if format in self.format_fns:
            self.format_fns[format](self)

    def name_path(self, template):
        return str(self.path.joinpath(template.format(self.name)))


class Key(ConvertMixin):

    """A representation of the key file"""

    def __init__(self, name, path, key_alg):
        self.name = name
        self.key_alg = key_alg
        self.path = path
        self.file = None
        self.formats = {}

        self.create_key()

    def create_key(self):
        """ Create a private key with the given algorithmen

        Args:
            self --

        Returns:
            the path to the newly created private key file as a string.
        """
        self.file = self.name_path('{}.key.pem'.format(self.name))
        cmd = 'genpkey -outform PEM -algorithm {} -out {{}}'.format(self.key_alg)
        openssl(cmd, self.file)
        return self.file

    def convert_to_der(self):
        if 'DER' not in self.formats:
            der_file = self.name_path('{}.key.der')
            openssl('pkey -outform DER -in {} -out {}', self.file, der_file)
            self.formats['DER'] = der_file

    format_fns = {'DER': convert_to_der}


class Certificate(ConvertMixin):
    """ Represantation of a certificate """

    def __init__(self, name, path, key, subject_str):
        """ Create the certificate for the service

        Args:
            self --
            subject_str -- the subject string for the certificate

        """
        self.name = name
        self.path = path
        self.key = key
        self.file = None
        self.formats = {}

        self.file = self.name_path('{}.cer.pem')
        openssl('req -new -days 365 -nodes -x509 -outform PEM -subj {} -out {} -key {}',
                subject_str,
                self.file,
                self.key.file)

    def get_cert_with_alias(self):
        file = self.name_path('{}.cer.trusted.pem')
        openssl('x509 -in {} -setalias {} -out {}',
                self.file, self.name, file)
        return file

    def convert_to_der(self):
        if 'DER' not in self.formats:
            der_file = self.name_path('{}.cer.der')
            openssl('x509 -outform DER -in {} -out {}', self.file, der_file)
            self.formats['DER'] = der_file

    format_fns = {'DER': convert_to_der}


class Service(ConvertMixin):

    """A Service object hold the name and certificate for a service"""

    def __init__(self, name, key_alg, out_path, confidant_names, formats, subject_str, pw_len=10):
        self.name = name
        self.confidants = confidant_names
        self.path = mkdir(out_path.joinpath(name))
        self.password = random_password(pw_len)
        self.confidat_file = None
        self.key = Key(name, self.path, key_alg)
        self.cert = Certificate(name, self.path, self.key, subject_str)
        self.formats = None

        self.set_formats(formats)

    def set_formats(self, formats):
        format_set = set(formats)
        self.formats = dict.fromkeys(format_set, None)
        self.formats['PEM'] = {'key': self.key.file, 'cert': self.cert.file}

    def convert_to_der(self):
        self.key.convert_to_der()
        self.cert.convert_to_der()
        self.formats['DER'] = {'key': self.key.formats['DER'], 'cert': self.cert.formats['DER']}

    def convert_to_pkcs12_keystore(self):
        if self.formats['PKCS12'] is None:
            filename = '{}.keystore.p12'.format(self.name)
            store = str(self.path.joinpath(filename))
            with password_pipe(self.password) as pipe_fd:
                passout = 'fd:{}'.format(pipe_fd)
                openssl_with_fds('pkcs12 -export -in {} -inkey {} -name {} -passout {} -out {}', (pipe_fd,),
                                 self.cert.get_cert_with_alias(), self.key.file, self.name, passout, store)
            self.formats['PKCS12'] = store

    def convert_to_jks_keystore(self):
        self.convert_to_pkcs12_keystore()
        self.convert_to_der()
        filename = '{}.keystore.jks'.format(self.name)
        keystore = self.path.joinpath(filename)
        try:
            keystore.unlink()
        except FileNotFoundError:
            pass
        keystore_str = str(keystore)
        keytool('-importkeystore -noprompt '
                '-srcstoretype PKCS12 -deststoretype JKS '
                '-srcstorepass {password} -deststorepass {password} '
                '-srckeystore {srckeystore} -destkeystore {destkeystore} ',
                password=self.password,
                srckeystore=self.formats['PKCS12'],
                destkeystore=keystore_str)
        self.formats['JKS'] = {'keystore': keystore_str}

    def create_truststore(self, service_dict):
        self.create_pem_truststore(service_dict)
        if 'JKS' in self.formats:
            self.create_jks_truststore(service_dict)

    def create_jks_truststore(self, service_dict):
        filename = '{}.truststore.jks'.format(self.name)
        truststore = self.path.joinpath(filename)
        try:
            truststore.unlink()
        except FileNotFoundError:
            pass
        truststore_str = str(truststore)
        for confidant in self.confidants:
            confidant_cert = service_dict[confidant].cert
            if 'DER' not in confidant_cert.formats:
                confidant_cert.convert_to_der()
            der_cert = confidant_cert.formats['DER']
            keytool('-importcert -noprompt -alias {alias} -file {cert} -keystore {keystore} -storetype JKS -storepass {password}',
                    alias=confidant,
                    cert=der_cert,
                    keystore=truststore_str,
                    password=self.password)
        self.formats['JKS']['truststore'] = truststore_str

    def create_pem_truststore(self, service_dict):
        filename = '{}.truststore.pem'.format(self.name)
        services_confidants = self.path.joinpath(filename)
        with services_confidants.open('w') as confidants_file:
            for confidant in self.confidants:
                with open(service_dict[confidant].cert.file) as confidant_cert:
                    for line in confidant_cert:
                        confidants_file.write(line)
        self.confidat_file = str(services_confidants)

    format_fns = {'DER': convert_to_der, 'PKCS12': convert_to_pkcs12_keystore, 'JKS': convert_to_jks_keystore}


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


def random_password(length):
    """ Create Random strings

    The random string is created out of the set of `string.ascii_letters` and `string.digits`.

    Args:
        length -- the length of the new random string

    Returns:
        A random string cosisting out of ascii letters and the decimal digits.
    """
    choices = string.ascii_letters + string.digits
    randdom_gen = (random.SystemRandom().choice(choices) for _ in range(length))
    return ''.join(randdom_gen)
