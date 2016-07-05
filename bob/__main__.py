import bob
import argparse
import shutil
import sys
import json
import pathlib
import time


CONFIG = {
        "default_key_alg": "EC -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve",
        "out_path": "./certs",
        "cert_file": "cert.pem",
        "key_file": "key.pem",
        "services": [],
        "password_length": 10,
        "wait": 0
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


def create_credentials(out_path, services, default_key_alg, pw_len):
    """ Create the creadentials for all services

    Args:
        out_path -- the path where the new certificates should be stored
        services -- a list of the services
        default_key_alg -- the default algorithmen for which keys should be created
    """



    service_dict = {}

    for s in services:
        service_name = s['name']
        subject_str = s['subject_str']
        key_alg = s.get('key_alg', default_key_alg)
        confidant_names = s['confidants']
        formats = ('DER', 'PKCS12', 'JKS')
        service = bob.Service(service_name, key_alg, out_path, confidant_names, formats, subject_str, pw_len)
        service_dict[service.name] = service

    return service_dict


def create_truststore(service_dict, cert_path, wait_secs):
    needed_confidants = set()
    existing_certs = {}

    for service in service_dict.values():
        for confidant in service.confidants:
            needed_confidants.add(confidant)
    
    for i in range(1,10):
        time.sleep(wait_secs * i)
        if  len(needed_confidants - set(existing_certs.keys())) == 0:
            break

        preexisting_certs = {}
        
        for service_dir in cert_path.iterdir():
            existing_cert = bob.PreexsitingCertificate(service_dir)
            preexisting_certs[existing_cert.name] = existing_cert

        preexisting_certs.update(service_dict)
        existing_certs = preexisting_certs

    try:
        for service in service_dict.values():
            for format in service.formats:
                service.convert_to(format)
            service.create_truststore(existing_certs)
    except KeyError as e:
        print('Could not create TrustStore"!',
              '  There was no certificate for the service {}'.format(e.args),
              sep='\n', file=sys.stderr)
        sys.exit(2)


def setup(config):
    return bob.mkdir(pathlib.Path(config['out_path']))


def main():
    """ Main function """
    if not test_for_cmds():
        sys.exit(1)
    args = parse_args()
    config = read_config(CONFIG, args.config)

    cert_path = setup(config)
    services = config['services']
    default_key_alg = config['default_key_alg']
    pw_len = config['password_length']
    wait_secs = config['wait']

    services = create_credentials(cert_path, services, default_key_alg, pw_len)

    create_truststore(services, cert_path, wait_secs)

    print_services(services.values())

if __name__ == "__main__":
    main()
