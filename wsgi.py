from statusserv.serv import start

run: bool = False
if __name__ == '__main__':
   run = True
app = start(run)