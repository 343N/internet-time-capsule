import os, dotenv

def moveTerminalCursor(up=0, down=0, left=0, right=0):
    if not (up or down or left or right):
        return
    
    upstr = "\033[%dA" % up if up else ""
    downstr = "\033[%dB" % down if down else ""
    leftstr = "\033[%dD" % left if left else ""
    rightstr = "\033[%dC" % right if right else ""


    print(f"{upstr}{downstr}{leftstr}{rightstr}", end="")



# container so we can use dot notation for things :)
class Container(object):

    def __init__(self):
        self.objCount = 0
        super().__init__()

    

    @classmethod
    def fromDict(cls, d, parent=None):
        c = Container()
        # print(d, type(d))
        for k,v in d.items():
            # print(k, v)
            # if (isinstance(v, d)):
            #     setattr(c, k, cls.fromDict(v, c))
            # else:
            setattr(c, k, v)

        return c

    def printAll(self):
        for k,v in self.__dict__.items():
            print(k, v, type(v))

    def __getattr__(self, attribute):
        try:
            return self.__dict__[attribute]
        except KeyError:
            super().__setattr__(attribute, Container())
            return self.attribute

    def __setattr__(self, attribute, value):
        if (attribute != "objCount"):
            if (value == None):
                del self.attribute
                self.objCount -= 1
            elif (attribute not in self.__dict__):
                self.objCount += 1

        self.__dict__[attribute] = value

