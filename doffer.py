#!/usr/bin/env python

import macholib.MachO as Macho
import macholib.mach_o as macho
from macholib.ptypes import *
import struct

DOF_ENCODE_LSB = 1
DOF_ENCODE_MSB = 2

class dofh_ident_t(Structure):
    _fields_ = (
        ('mag0', p_ubyte),
        ('mag1', p_ubyte),
        ('mag2', p_ubyte),
        ('mag3', p_ubyte),
        ('model', p_ubyte),
        ('encoding', p_ubyte),
        ('version', p_ubyte),
        ('difvers', p_ubyte),
        ('difireg', p_ubyte),
        ('diftreg', p_ubyte),
        ('pad0', p_ubyte), ('pad1', p_ubyte), ('pad2', p_ubyte),
        ('pad3', p_ubyte), ('pad4', p_ubyte), ('pad5', p_ubyte),
    )

class dof_hdr_t(Structure):
    _fields_ = (
        ('ident', dofh_ident_t),
        ('flags', p_ulong),
        ('hdrsize', p_ulong),
        ('secsize', p_ulong),
        ('secnum', p_ulong),
        ('secoff', p_ulonglong),
        ('loadsz', p_ulonglong),
        ('filesz', p_ulonglong),
        ('pad', p_ulonglong),
    )

(DOF_SECT_NONE, DOF_SECT_COMMENTS, DOF_SECT_SOURCE, DOF_SECT_ECBDESC,
 DOF_SECT_PROBEDESC, DOF_SECT_ACTDESC, DOF_SECT_DIFOHDR, DOF_SECT_DIF,
 DOF_SECT_STRTAB, DOF_SECT_VARTAB, DOF_SECT_RELTAB, DOF_SECT_TYPTAB,
 DOF_SECT_URELHDR, DOF_SECT_KRELHDR, DOF_SECT_OPTDESC, DOF_SECT_PROVIDER,
 DOF_SECT_PROBES, DOF_SECT_PRARGS, DOF_SECT_PROFFS, DOF_SECT_INTTAB,
 DOF_SECT_UTSNAME, DOF_SECT_XLTAB, DOF_SECT_XLMEMBERS, DOF_SECT_XLIMPORT,
 DOF_SECT_XLEXPORT, DOF_SECT_PREXPORT, DOF_SECT_PRENOFFS) = range(27)

SECTION_NAME_MAP = {
    DOF_SECT_NONE: 'none', DOF_SECT_COMMENTS: 'comments',
    DOF_SECT_SOURCE:'source', DOF_SECT_ECBDESC: 'ecb desc',
    DOF_SECT_PROBEDESC: 'probe desc', DOF_SECT_ACTDESC: 'act desc',
    DOF_SECT_DIFOHDR: 'difo header', DOF_SECT_DIF: 'dif',
    DOF_SECT_STRTAB: 'string table', DOF_SECT_VARTAB: 'difv table',
    DOF_SECT_RELTAB: 'rel table', DOF_SECT_TYPTAB: 'diftype table',
    DOF_SECT_URELHDR: 'user relocations',
    DOF_SECT_KRELHDR: 'kernel relocations',
    DOF_SECT_OPTDESC: 'optdesc array', DOF_SECT_PROVIDER: 'provider',
    DOF_SECT_PROBES: 'probe array', DOF_SECT_PRARGS: 'probe arg mappings',
    DOF_SECT_PROFFS: 'probe arg offsets', DOF_SECT_INTTAB: 'uint64 array',
    DOF_SECT_UTSNAME: 'utsname', DOF_SECT_XLTAB: 'xlref array',
    DOF_SECT_XLMEMBERS: 'xlmember array', DOF_SECT_XLIMPORT: 'xlator import',
    DOF_SECT_XLEXPORT: 'xlator export', DOF_SECT_PREXPORT: 'exported objects',
    DOF_SECT_PRENOFFS: 'enabled offsets',
}

class dof_sec_t(Structure):
    _fields_ = (
        ('type', p_ulong),
        ('align', p_ulong),
        ('flags', p_ulong),
        ('entsize', p_ulong),
        ('offset', p_ulonglong),
        ('size', p_ulonglong),
    )

dof_secidx_t = p_ulong
dof_stridx_t = p_ulong

# we are assuming little-endian here.
class dof_attr_t(Structure):
    _fields_ = (
        ('pad', p_ubyte),
        ('class', p_ubyte),
        ('data', p_ubyte),
        ('name', p_ubyte),
    )

class dof_provider_t(Structure):
    _fields_ = (
        ('strtab', dof_secidx_t),
        ('probes', dof_secidx_t),
        ('prargs', dof_secidx_t),
        ('proffs', dof_secidx_t),
        ('name', dof_stridx_t),
        ('provattr', dof_attr_t),
        ('modattr', dof_attr_t),
        ('funcattr', dof_attr_t),
        ('nameattr', dof_attr_t),
        ('argsattr', dof_attr_t),
        ('prenoffs', dof_secidx_t),
    )

class dof_probe_t(Structure):
    _fields_ = (
        ('addr', p_ulonglong),
        ('func', dof_stridx_t),
        ('name', dof_stridx_t),
        ('nargv', dof_stridx_t),
        ('xargv', dof_stridx_t),
        ('argidx', p_ulong),
        ('offidx', p_ulong),
        ('nargc', p_ubyte),
        ('xargc', p_ubyte),
        ('noffs', p_ushort),
        ('enoffidx', p_ulong),
        ('nenoffs', p_ushort),
        ('pad1', p_ushort),
        ('pad2', p_ulong),
    )

class Doffy(object):
    def __init__(self, filename):
        self.filename = filename
        self.mo = Macho.MachO(filename)
    
    def sanity(self):
        for header in self.mo.headers:
            print 'HEADER', header
            for load_cmd, cmd, data in header.commands:
                if isinstance(cmd, macho.segment_command):
                    print '  segment "%s"' % (cmd.segname,)
                    for section in data:
                        print '    section', section.sectname, hex(section.offset)
                else:
                    print '  gencmd', cmd
    
    def get_dof_sections(self):
        dof_sections = []
        for header in self.mo.headers:
            for load_cmd, cmd, data in header.commands:
                if (isinstance(cmd, macho.segment_command) and
                        cmd.segname.startswith('__TEXT')):
                    for section in data:
                        if section.sectname.startswith('__dof'):
                            dof_sections.append(section)
        return dof_sections

    def load_dof(self, f, section):
        print 'Section:', section.sectname
        BASE_OFFSET = section.offset
        f.seek(section.offset)
        ident = dofh_ident_t.from_fileobj(f)
        if ident.encoding == DOF_ENCODE_LSB:
            kw = {'_endian_': '<'}
        else:
            kw = {'_endian_': '>'}
        print 'decode keywords', kw
        
        f.seek(section.offset)
        header = dof_hdr_t.from_fileobj(f, **kw)
        
        strtab = None
        def getstr(idx):
            eoff = strtab.index('\0', idx)
            return strtab[idx:eoff]
        
        dof_secs = []
        for iSec in range(header.secnum):
            f.seek(BASE_OFFSET + header.secoff + iSec * header.secsize)
            dof_sec = dof_sec_t.from_fileobj(f, **kw)
            dof_secs.append(dof_sec)
        
        for dof_sec in dof_secs:
            if dof_sec.type == DOF_SECT_PROVIDER:
                print 'found provider!'
                f.seek(BASE_OFFSET + dof_sec.offset)
                provider = dof_provider_t.from_fileobj(f, **kw)
                
                # -- load the sttab
                if dof_secs[provider.strtab].type == DOF_SECT_STRTAB:
                    strtab_sec = dof_secs[provider.strtab]
                    f.seek(BASE_OFFSET + strtab_sec.offset)
                    strtab = f.read(strtab_sec.size)
                    DO_EVIL = True
                    if DO_EVIL:
                        strtab_evil = strtab.replace('javascript', 'wavascript')
                        f.seek(BASE_OFFSET + strtab_sec.offset)
                        f.write(strtab_evil)
                
                print '  Name:', getstr(provider.name)
                # -- load the offsets
                if dof_secs[provider.proffs].type == DOF_SECT_PROFFS:
                    offsets_sec = dof_secs[provider.proffs]
                    f.seek(BASE_OFFSET + offsets_sec.offset)
                    num_offsets = offsets_sec.size / 4
                    print '  Offset Count:', num_offsets
                    probe_offsets = struct.unpack(kw['_endian_'] + ('%dL' % (num_offsets,)),
                                                  f.read(offsets_sec.size))
                else:
                    print '  *** No Probe Offsets!'
                    probe_offsets = []
                
                # load the enabled offsets
                # (ignore things that aren't actually prenoffs)
                if dof_secs[provider.prenoffs].type == DOF_SECT_PRENOFFS:
                    en_offsets_sec = dof_secs[provider.prenoffs]
                    f.seek(BASE_OFFSET + en_offsets_sec.offset)
                    num_en_offsets = en_offsets_sec.size / 4
                    print '  Enabled Offset Count:', num_en_offsets
                    probe_en_offsets = struct.unpack(kw['_endian_'] + ('%dL' % (num_en_offsets,)),
                                                     f.read(en_offsets_sec.size))
                else:
                    print '  *** No Probe Enable Offsets!'
                    probe_en_offsets = []
                
                # -- load the probes
                probe_sec = dof_secs[provider.probes]
                probe_end_off = BASE_OFFSET + probe_sec.offset + probe_sec.size
                f.seek(BASE_OFFSET + probe_sec.offset)
                probes = []
                while f.tell() < probe_end_off:
                    probe = dof_probe_t.from_fileobj(f, **kw)
                    print '    probe:', getstr(probe.func), ':', getstr(probe.name) # getstr(probe.nargv), getstr(probe.xargv)
                    #print '         ', probe.offidx, probe.noffs, probe.enoffidx, probe.nenoffs
                    offsets = probe_offsets[probe.offidx:probe.offidx+probe.noffs]
                    enable_offsets = probe_en_offsets[probe.enoffidx:probe.enoffidx+probe.nenoffs]
                    print '       offsets:', ', '.join(map(hex, offsets))
                    print '       enable offsets:', ', '.join(map(hex, enable_offsets))
                
            else:
                print '(found %s)' % (SECTION_NAME_MAP[dof_sec.type],)


    def get_dof_data(self):        
        self.dofs = {}
        f = open(self.filename, 'rb+')
        for section in self.get_dof_sections():
            dof = self.load_dof(f, section)
        f.close()

if __name__ == '__main__':
    import sys
    patrick = Doffy(sys.argv[1])
    patrick.sanity()
    print '-' * 40
    patrick.get_dof_data()
