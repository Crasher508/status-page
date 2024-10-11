from statusserv.serv import start

app = None
run: bool = False
if __name__ == '__main__':
   run = True
app = start(run)