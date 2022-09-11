#!/usr/bin/env python3

# Copyright (c) 2016-2022, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause

"""
This program parses the output from pcap.compile() to visualize the CFG after
each optimize phase.

Usage guide:
1. Enable optimizer debugging code when configure libpcap,
   and build libpcap & the test programs
       ./configure --enable-optimizer-dbg
       make
       make tests
2. Run filtertest to compile BPF expression and produce the CFG as a
   DOT graph, save to output a.txt
       python tests/filtertest.py -g EN10MB host 192.168.1.1 > a.txt
3. Send a.txt to this program's standard input
       cat a.txt | python tests/visopts.py
   (Graphviz must be installed)
4. Step 2&3 can be merged:
       python tests/filtertest.py -g EN10MB host 192.168.1.1 | python tests/visopts.py
5. The standard output is something like this:
       generated files under directory: /tmp/visopts-W9ekBw
         the directory will be removed when this programs finished.
       open this link: http://localhost:39062/expr1.html
6. Open the URL at the 3rd line in a browser.

Note:
1. The CFG is translated to SVG images, expr1.html embeds them as external
   documents. If you open expr1.html as local file using file:// protocol, some
   browsers will deny such requests so the web page will not work properly.
   For Chrome, you can run it using the following command to avoid this:
       chromium --disable-web-security
   That's why this program starts a localhost HTTP server.
2. expr1.html uses jQuery from https://ajax.googleapis.com, so it needs Internet
   access to work.
"""

import sys
import os
import string

html_template = string.Template("""
<html>
  <head>
    <title>BPF compiler optimization phases for "${expr_html}"</title>
    <style type="text/css">
      .hc {
         /* half width container */
         display: inline-block;
         float: left;
         width: 50%;
      }
    </style>

    <script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"/></script>
    <!--script type="text/javascript" src="./jquery.min.js"/></script-->
    <script type="text/javascript">
      var expr = '${expr_json}';
      var exprid = 1;
      var gcount = ${gcount};
      var logs = JSON.parse('${logs}');
      logs[gcount] = "";

      var leftsvg = null;
      var rightsvg = null;

      function gurl(index) {
         index += 1;
         if (index < 10)
           s = "00" + index;
         else if (index < 100)
           s = "0" + index;
         else
           s = "" + index;
         return "./expr" + exprid + "_g" + s + ".svg"
      }

      function annotate_svgs() {
         if (!leftsvg || !rightsvg) return;

         $$.each([$$(leftsvg), $$(rightsvg)], function() {
           $$(this).find("[id|='block'][opacity]").each(function() {
             $$(this).removeAttr('opacity');
            });
          });

         $$(leftsvg).find("[id|='block']").each(function() {
           var has = $$(rightsvg).find("#" + this.id).length != 0;
           if (!has) $$(this).attr("opacity", "0.4");
           else {
             $$(this).click(function() {
                var target = $$(rightsvg).find("#" + this.id);
                var offset = $$("#rightsvgc").offset().top + target.position().top;
                window.scrollTo(0, offset);
                target.focus();
             });
           }
          });
         $$(rightsvg).find("[id|='block']").each(function() {
           var has = $$(leftsvg).find("#" + this.id).length != 0;
           if (!has) $$(this).attr("opacity", "0.4");
           else {
             $$(this).click(function() {
                var target = $$(leftsvg).find("#" + this.id);
                var offset = $$("#leftsvgc").offset().top + target.position().top;
                window.scrollTo(0, offset);
                target.focus();
             });
           }
          });
      }

      function init_svgroot(svg) {
         svg.setAttribute("width", "100%");
         svg.setAttribute("height", "100%");
      }
      function wait_leftsvg() {
         if (leftsvg) return;
         var doc = document.getElementById("leftsvgc").getSVGDocument();
         if (doc == null) {
            setTimeout(wait_leftsvg, 500);
            return;
         }
         leftsvg = doc.documentElement;
         //console.log(leftsvg);
         // initialize it
         init_svgroot(leftsvg);
         annotate_svgs();
      }
      function wait_rightsvg() {
         if (rightsvg) return;
         var doc = document.getElementById("rightsvgc").getSVGDocument();
         if (doc == null) {
            setTimeout(wait_rightsvg, 500);
            return;
         }
         rightsvg = doc.documentElement;
         //console.log(rightsvg);
         // initialize it
         init_svgroot(rightsvg);
         annotate_svgs();
      }
      function load_left(index) {
        var url = gurl(index);
        var frag = "<embed id='leftsvgc'  type='image/svg+xml' pluginspage='https://www.adobe.com/svg/viewer/install/' src='" + url + "'/>";
        $$("#lsvg").html(frag);
        $$("#lcomment").html(logs[index]);
        $$("#lsvglink").attr("href", url);
        leftsvg = null;
        wait_leftsvg();
      }
      function load_right(index) {
        var url = gurl(index);
        var frag = "<embed id='rightsvgc' type='image/svg+xml' pluginspage='https://www.adobe.com/svg/viewer/install/' src='" + url + "'/>";
        $$("#rsvg").html(frag);
        $$("#rcomment").html(logs[index]);
        $$("#rsvglink").attr("href", url);
        rightsvg = null;
        wait_rightsvg();
      }

      $$(document).ready(function() {
        for (var i = 0; i < gcount; i++) {
          var opt = "<option value='" + i + "'>loop" + i + " -- " + logs[i] + "</option>";
          $$("#lselect").append(opt);
          $$("#rselect").append(opt);
        }
        var on_selected = function() {
          var index = parseInt($$(this).children("option:selected").val());
          if (this.id == "lselect")
             load_left(index);
          else
             load_right(index);
        }
        $$("#lselect").change(on_selected);
        $$("#rselect").change(on_selected);

        $$("#backward").click(function() {
          var index = parseInt($$("#lselect option:selected").val());
          if (index <= 0) return;
          $$("#lselect").val(index - 1).change();
          $$("#rselect").val(index).change();
        });
        $$("#forward").click(function() {
          var index = parseInt($$("#rselect option:selected").val());
          if (index >= gcount - 1) return;
          $$("#lselect").val(index).change();
          $$("#rselect").val(index + 1).change();
        });

        if (gcount >= 1) $$("#lselect").val(0).change();
        if (gcount >= 2) $$("#rselect").val(1).change();
      });
    </script>
  </head>
  <body style="width: 96%">
    <div>
      <h1>${expr_html}</h1>
      <div style="text-align: center;">
        <button id="backward" type="button">&lt;&lt;</button>
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        <button id="forward" type="button">&gt;&gt;</button>
      </div>
    </div>
    <br/>
    <div style="clear: both;">
       <div class="hc lc">
        <select id="lselect"></select>
        <a id="lsvglink" target="_blank">open this svg in browser</a>
        <p id="lcomment"></p>
       </div>
       <div class="hc rc">
        <select id="rselect"></select>
        <a id="rsvglink" target="_blank">open this svg in browser</a>
        <p id="rcomment"></p>
       </div>
    </div>
    <br/>
    <div style="clear: both;">
       <div id="lsvg"  class="hc lc"></div>
       <div id="rsvg" class="hc rc"></div>
    </div>
  </body>
</html>
""")


def write_html(expr, gcount, logs):
    import html
    import json

    # In the Python 2.7 version this used to be str.encode('string-escape'),
    # which was a normal string, but in Python 3 the "string_escape" encoding
    # no longer exists and even with the "unicode_escape" encoding encode()
    # always returns a binary string.  So let's just escape the single quotes
    # here and hope the result is a valid JavaScript string literal.
    def encode(s):
        return s.replace("'", "\'")

    mapping = {
        'expr_html': html.escape(expr),
        'expr_json': encode(expr),
        'gcount': gcount,
        'logs': encode(json.dumps([s.strip().replace("\n", "<br/>") for s in logs])),
    }
    with open("expr1.html", "wt") as f:
        f.write(html_template.safe_substitute(mapping))


def render_on_html(infile):
    import subprocess

    expr = None
    gid = 1
    log = ""
    dot = ""
    indot = 0
    logs = []

    for line in infile:
        if line.startswith("machine codes for filter:"):
            expr = line[len("machine codes for filter:"):].strip()
            break
        elif line.startswith("digraph BPF {"):
            indot = 1
            dot = line
        elif indot:
            dot += line
            if line.startswith("}"):
                indot = 2
        else:
            log += line

        if indot == 2:
            try:
                svg = subprocess.check_output(['dot', '-Tsvg'], input=dot, universal_newlines=True)
            except OSError as ose:
                print("Failed to run 'dot':", ose)
                print("(Is Graphviz installed?)")
                return False
            except subprocess.CalledProcessError as cpe:
                print("Got an error from the 'dot' process: ", cpe)
                return False

            with open("expr1_g%03d.svg" % gid, "wt") as f:
                f.write(svg)

            logs.append(log)
            gid += 1
            log = ""
            dot = ""
            indot = 0

    if indot != 0:
        # unterminated dot graph for expression
        return False
    if expr is None:
        # BPF parser encounter error(s)
        return False

    write_html(expr, gid - 1, logs)
    return True


def run_httpd():
    import http.server

    httpd = http.server.HTTPServer(("localhost", 0), http.server.SimpleHTTPRequestHandler)
    print("open this link: http://localhost:{}/expr1.html".format(httpd.server_port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main(argv=sys.argv[1:]):
    import tempfile
    import atexit
    import shutil

    if '-h' in argv or '--help' in argv:
        print(__doc__)
        return 0

    cwd = os.getcwd()
    try:
        temp_dir = tempfile.mkdtemp(prefix="visopts-")
        atexit.register(shutil.rmtree, temp_dir)
        os.chdir(temp_dir)
        print("generated files under directory: {}".format(temp_dir))
        print("  the directory will be removed when this program has finished.")

        if not render_on_html(sys.stdin):
            return 1

        run_httpd()
    finally:
        os.chdir(cwd)

    return 0


if __name__.rpartition(".")[-1] == "__main__":
    exit(main())
