import bob
import argparse
import shutil
import sys
import json
import pathlib


CONFIG = {
        "default_key_alg": "EC -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve",
        "out_path": "./certs",
        "cert_file": "cert.pem",
        "key_file": "key.pem",
        "services": [],
        "password_length": 10
}


def parse_args():
    """ Prarse the arguments """
    parser = argparse.ArgumentParser(description='Bob the certificate builder.')
    parser.add_argument('config', default='./config/cert_conf.json',
                        type=argparse.FileType('r'),
                        help='configuration file for the creation of certificates')
    return parser.parse_args()


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
        config.update(loaded_conf["bob"])
        return config


def test_for_cmds():
    if shutil.which('openssl') is None:
        print('OpenSSL is missing')
        return False

    if shutil.which('keytool') is None:
        print('Java KeyTool is missing')
        return False
    return True


def print_services(services):
    gen = {service.name: {'password': service.password, 'formats': service.formats}
           for service in services}
    print(json.dumps(gen))


def create_credentials(config):
    """ Create the creadentials for all services

    Args:
        out_path -- the path where the new certificates should be stored
        service -- a list of the services
        default_key_alg -- the default algorithmen for which keys should be created
    """

    out_path = setup(config)

    services = config['services']
    default_key_alg = config['default_key_alg']
    pw_len = config['password_length']

    service_dict = {}

    for s in services:
        service_name = s['name']
        subject_str = s['subject_str']
        key_alg = s.get('key_alg', default_key_alg)
        confidant_names = s['confidants']
        formats = ('DER', 'PKCS12', 'JKS')
        service = bob.Service(service_name, key_alg, out_path, confidant_names, formats, subject_str, pw_len)
        service_dict[service.name] = service

    for service in service_dict.values():
        for format in service.formats:
            service.convert_to(format)
        service.create_truststore(service_dict)

    return service_dict.values()


def setup(config):
    return bob.mkdir(pathlib.Path(config['out_path']))


def main():
    """ Main function """
    if not test_for_cmds():
        sys.exit(1)
    args = parse_args()
    config = read_config(CONFIG, args.config)

    services = create_credentials(config)
    print_services(services)

if __name__ == "__main__":
    main()
