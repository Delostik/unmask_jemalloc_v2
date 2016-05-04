unmask_jemalloc - De Mysteriis Dom jemalloc
===========================================

This version is based on https://github.com/argp/unmask_jemalloc, add some
adjustment changes:
    
    support jemalloc 4.x

    support i386, x86_64, arm

WARNING: still something wrong in je_parse_chunks
===========================================
A gdb/Python extension to unmask and bring to light the internals of the
various jemalloc flavors.

This new release of unmask_jemalloc specifically targets Mozilla Firefox
and is a complete rewrite of the initial version of the utility as
published in our Phrack paper on exploiting jemalloc:

http://phrack.org/issues.html?issue=68&id=10#article

The original slide deck from our Black USA 2012 presentation on the subject
of exploiting Firefox/jemalloc is available at:

https://www.blackhat.com/html/bh-us-12/bh-us-12-archives.html#Argyroudis

The updated slide deck is at:

http://census-labs.com/news/2012/08/03/blackhat-usa-2012-update/

You can load unmask_jemalloc by including the following in your gdbinit (or
issuing them at the gdb prompt):

    python import sys
    python sys.path.append("/path/to/unmask_jemalloc")
    source /path/to/unmask_jemalloc/unmask_jemalloc.py

Then from gdb use the jehelp command to get details on the commands
provided by unmask_jemalloc:

    gdb $ jehelp

    [unmask_jemalloc] available commands:
    [unmask_jemalloc]   jechunks               : dump info on all available chunks
    [unmask_jemalloc]   jearenas               : dump info on jemalloc arenas
    [unmask_jemalloc]   jeruns [-c]            : dump info on jemalloc runs (-c for current runs only)
    [unmask_jemalloc]   jebins                 : dump info on jemalloc bins
    [unmask_jemalloc]   jeregions <size class> : dump all current regions of the given size class
    [unmask_jemalloc]   jesearch [-c] <hex>    : search the heap for the given hex value (-c for current runs only)
    [unmask_jemalloc]   jedump [filename]      : dump all available info to screen (default) or file
    [unmask_jemalloc]   jeparse                : (re)parse jemalloc structures from memory
    [unmask_jemalloc]   jeversion              : output version number
    [unmask_jemalloc]   jehelp                 : this help message



