import time

import web

import mac
import srp
import util

render = web.template.render('html/')

urls = ('/', 'index', '/hmac', 'hmac', '/login', 'login')
key = None

login_form = web.form.Form(
    web.form.Textbox('email'),
    web.form.Password('password'),
    web.form.Button('Login'),
)


def start_server():
    app = web.application(urls, globals())
    app.run()


class index():
    def GET(self):
        return 'Cryptopals Landing Page'


class hmac():
    def POST(self):
        data = web.input()
        valid = self.validate_sig(data.file, data.sig, int(data.stime))
        if valid:
            web.ctx.status = '200 OK'
            return 'explicit 200'
        else:
            web.ctx.status = '500 Internal Server Error'
            return 'explicit 500'

    def validate_sig(self, file, sig, stime):
        key = 'YELLOW SUBMARINE'
        file = file.encode('ascii')
        computed_sig = mac.hmac_sha1(key, file)
        return self.insecure_compare(sig, computed_sig, stime)

    def insecure_compare(self, sig1, sig2, stime):
        for b1, b2 in zip(sig1.decode('hex'), sig2.decode('hex')):
            if b1 != b2:
                return False
            time.sleep(stime / 1000.0)

        return True


class login():
    def GET(self):
        form = login_form()
        return render.login(form)

    def POST(self):
        form = login_form()
        if not form.validates():
            return render.login(form)
        else:
            clientlogic = srp.Client('foo@bar.com', 'password', tampered=True)
            serverlogic = srp.Server(form.d.email, form.d.password)

            clientlogic.set_server(serverlogic)
            serverlogic.set_client(clientlogic)
            clientlogic.initiate()

            return 'Success' if clientlogic.check_hmac() else 'Failure'

if __name__ == '__main__':
    start_server()
