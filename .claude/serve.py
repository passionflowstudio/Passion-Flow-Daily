import http.server, socketserver, os
os.chdir('/Users/joshuaebalo/Desktop/Passion Flow Daily')
PORT = 8000
Handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(('', PORT), Handler) as httpd:
    httpd.serve_forever()
