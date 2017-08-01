#!/usr/bin/env python3

import argparse
import json
import re
import sys

class RekallProfile:
    """ Rekall Profile Generator """

    def __init__(self, args):
        self.config_path = args.config
        self.sysmap_path = args.sysmap
        self.dict_config = {}
        self.dict_sysmap = {}
        self.dict_enums = {}
        self.dict_metadata = {}
        self.dict_revenums = {}
        self.dict_struct = {}
        self.dict_profile = {}
        self.profile_path = 'profile'
        self.profile = open(self.profile_path, 'w')

    def generate_profile(self):
        self.dict_profile['$CONFIG'] = self.dict_config
        self.dict_profile['$CONSTANTS'] = self.dict_sysmap
        self.dict_profile['$ENUMS'] = self.dict_enums
        self.dict_profile['$METADATA'] = self.dict_metadata
        self.dict_profile['$REVENUMS'] = self.dict_revenums
        self.dict_profile['$STRUCTS'] = self.dict_struct

        with open(self.profile_path, 'w') as profile:
            str = json.dumps(self.dict_profile, indent=2, sort_keys=True,
                             separators=(',', ': '))
            profile.write(str)

    def parse_sysmap_line(self, line):
        triple = line.split(' ')

        # Address limited to 48 bit.
        addr = int(triple[0], 16) & ((1<<48)-1)

        funcname = triple[2]

        self.dict_sysmap[funcname] = addr

    def parse_sysmap(self):
        with open(self.sysmap_path, 'r') as sysmap:
            for line in sysmap:
                self.parse_sysmap_line(line.rstrip('\n'))

    def parse_config_line(self, line):
        if not line:
            return

        stuple = line.split('=')

        confname = stuple[0]
        confval = stuple[1].replace('"', '')

        self.dict_config[confname] = confval

    def parse_config(self):
        with open(self.config_path, 'r') as config:
            for line in config:
                # Skip comments.
                if line.startswith('#'):
                    continue
                self.parse_config_line(line.rstrip('\n'))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-c', '--config', help='Path to Linux config')
    parser.add_argument('-s', '--sysmap', help='Path to Sytem.map')

    args = parser.parse_args()

    rp = RekallProfile(args)

    rp.parse_config()
    rp.parse_sysmap()
    rp.generate_profile()
