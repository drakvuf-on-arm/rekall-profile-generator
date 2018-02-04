#!/usr/bin/env python3

import argparse
import json
import r2pipe
import re
import sys

from pprint import pprint

class RekallProfile:
    """ Rekall Profile Generator """

    structs = [
        'cred',
        'mm_struct',
        'task_struct'
    ]

    types = {
        'u32' : 'unsigned int',
        'u64' : 'long long unsigned int',
    }

    meta_info = {
        'linux' : 'Linux'
    }

    def __init__(self, args):
        self.config_path = args.config
        self.sysmap_path = args.sysmap
        self.dwarf_path = args.dwarf
        self.dict_config = {}
        self.dict_sysmap = {}
        self.dict_enums = {}
        self.dict_metadata = {}
        self.dict_revenums = {}
        self.dict_struct = {}
        self.dict_profile = {}
        self.profile_path = 'profile'
        self.profile = open(self.profile_path, 'w')
        self.r2 = r2pipe.open(self.dwarf_path)

    def generate_profile(self):
        self.dict_profile['$CONFIG'] = self.dict_config
        self.dict_profile['$CONSTANTS'] = self.dict_sysmap
        self.dict_profile['$ENUMS'] = self.dict_enums
        self.dict_profile['$METADATA'] = self.dict_metadata
        self.dict_profile['$REVENUMS'] = self.dict_revenums
        self.dict_profile['$STRUCTS'] = self.dict_struct

        with open(self.profile_path, 'w') as profile:
            str = json.dumps(self.dict_profile, indent=1, sort_keys=True,
                             separators=(',', ': '))
            profile.write(str)

    def parse_sysmap_line(self, line):
        triple = line.split(' ')

        # We are not interested in the uninitialized data section.
        if triple[1].upper() == 'B' or triple[1] == 'd':
            return

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

    def parse_meta(self):
        str_meta = self.r2.cmd('ij')
        dict_meta = json.loads(str_meta)

        pprint(dict_meta)

        os = dict_meta['bin']['os']
        if os in RekallProfile.meta_info:
            self.dict_metadata['ProfileClass'] = RekallProfile.meta_info[os]
        else:
            self.dict_metadata['ProfileClass'] = os

        self.dict_metadata['Type'] = 'Profile'
        self.dict_metadata['Version'] = 1337
        self.dict_metadata['arch'] = dict_meta['bin']['arch']

    def parse_dwarf_struct(self, struct, t):
        rk_entry = [t]

        return rk_entry

    def parse_dwarf_pointer(self, pointer, t):
        rk_entry = ['Pointer', {
                        'target' : t,
                        'target_args' : None
                    }]

        return rk_entry

    def parse_dwarf_array(self, arr, t):
        rk_entry = {}
        # XXX: We do not allow more than one dim arrays!
        array_dim = arr['array_dimension'][0]

        if arr['pointer']:
            rk_entry = ['Array', {
                            'count' : array_dim,
                            'target' : 'Pointer',
                            'target_args' : {
                                'target' : t,
                                'target_args' : None
                            }
                        }]
        else:
            rk_entry = ['Array', {
                            'count' : array_dim,
                            'target' : t,
                            'target_args' : None
                        }]

        return rk_entry

    def parse_dwarf_field(self, field):
        rk_entry = {}

        offset = field['offset']
        t = field['type'].rstrip(' *')
        t = re.sub(r'(struct |const |volatile )', r'', t)

        # Normalize types.
        if t in RekallProfile.types:
            t = RekallProfile.types[t]

        rk_entry[field['name']] = [offset]

        if field['array']:
            rk_entry[field['name']].append(self.parse_dwarf_array(field, t))
        elif field['pointer']:
            rk_entry[field['name']].append(self.parse_dwarf_pointer(field, t))
        else:
            rk_entry[field['name']].append(self.parse_dwarf_struct(field, t))

        return rk_entry

    def parse_dwarf(self):
        self.r2.cmd('aaa')
        self.r2.cmd('iddi {0}'.format(self.dwarf_path))

        for struct in RekallProfile.structs:
            str_structdef = self.r2.cmd('idddj {0}'.format(struct))
            dict_structdef = json.loads(str_structdef)

            self.dict_struct[struct] = [dict_structdef['size']]

            dict_fields = {}
            for field in dict_structdef['members']:
                if not field['array'] and not field['pointer']:
                    """
                    The Linux kernel uses the macros
                    'randomized_struct_fields_(start|end)' to randomize struct
                    contents. The randomization yields an unnamed struct which
                    we have to detect and handle appropriately. Otherwise,
                    contents of that struct will not be listed in the profile.

                    Despite this radomization theme, we have to ensure that we
                    store the fields of the unnamed, randomized struct at the
                    same level as all other fields of the struct. That is,
                    instead of storing

                    "task_struct": [
                     3200,
                     {
                      {
                       "" : [
                        "acct_rss_mem1" : [
                         1864,
                         [...]
                        ],
                       ]
                      }
                      "thread_info" : [
                       0,
                       [...]
                      ]
                     }
                    ]

                    we have to ensure the following structure

                    "task_struct": [
                     3200,
                     {
                      "acct_rss_mem1" : [
                       1864,
                       [...]
                      ],
                      "thread_info" : [
                       0,
                       [...]
                      ]
                     }
                    ]

                    As such, we process fields that are not of type pointer or
                    array already in this function.

                    TODO: Future extensions should think about moving the
                    following part into the function parse_dwarf_field()

                    """
                    if field['name'] == "":
                        for f in field['members']:
                            dict_fields.update(self.parse_dwarf_field(f))
                    else:
                        dict_fields.update(self.parse_dwarf_field(field))
                else:
                    dict_fields.update(self.parse_dwarf_field(field))

            self.dict_struct[struct].append(dict_fields)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-c', '--config', help='Path to Linux config')
    parser.add_argument('-s', '--sysmap', help='Path to Sytem.map')
    parser.add_argument('-d', '--dwarf', help='Path to file with DWARF debugging information')

    args = parser.parse_args()

    rp = RekallProfile(args)

    rp.parse_config()
    rp.parse_sysmap()
    rp.parse_dwarf()
    rp.parse_meta()
    rp.generate_profile()
