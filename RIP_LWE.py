
#импорт используемых библиотек
import numpy as np
import random
from Crypto.Random.random import getrandbits
import math
from Crypto.Protocol.KDF import PBKDF2



#функция случайного выбора чисел из распредления Гаусса
def gauss_gen(sN,mu=0,sig=6.4):  
    e=[]
    for i in range(sN):
        e.append(math.floor(abs(random.gauss(mu,sig))))
    return (np.array(e))



#Приведение матрицы к модулю q
def module(matrix,q):
    for i in range(len(matrix)):
        try:
            for j in range(matrix[i]):
                matrix[i][j]=matrix[i][j]%q
        except:
            matrix[i]=matrix[i]%q
    return matrix


#создание случайной матрицы А 
def random_matrix_A(sN,n,a):
    matrix=[]
    for i in range(sN):
        n_raw=[]
        for j in range(n):
            new_el=PBKDF2(a, b'')
            a=new_el
            n_raw.append(int.from_bytes(new_el,"big"))
        matrix.append(n_raw)
    return(np.array(matrix))


#генерация случайный чисел для секретного ключа клиента
def random_numbers(n,q):
    s=[]
    for i in range(n):
        s.append(random.randint(0,q-1))
    return np.array(s)


# используемые константы
words=['a','b','c'] #словарь базы
p=833 
N=4096
n=2**5
sN=64
q=2**32
delt=math.floor(q/p)
a=b'\xafqz%\x84}I\x87\xa9\xdc\xeb\xff\x00\xbb\xc2\xa3' #общий секретный ключ


#класс базы данных (сервера)
class bd():
    def __init__(self, p, N, sN, q, delt,n,a):
        self.p=p
        self.N=N
        self.sN=sN
        self.q=q
        self.delt=delt
        self.n=n
        self.a=a
        #заполнение базы
    def generate_base(self,words):
        b=[]
        for i in range(self.N):
            b.append(int.from_bytes(words[i%3].encode(), "big")%q)
        self.b=module(b,self.p)
    def generate_A(self):
        self.A=module(random_matrix_A(self.sN,self.n,self.a),self.q)
    #Этап setup
    def setup(self):
        D=[]
        for i in range(0,self.N,sN):
            D.append(self.b[i:i+sN])
        self.D=np.array(D)
        self.generate_A()
        self.Hc=module(np.matmul(self.D,self.A),self.q)
        return self.Hc
    #Этап Answer
    def answer(self,c):
        return module(np.matmul(self.D,c),self.q)


#класс клиента
class client():
    
    def __init__(self, p, N, sN, q, delt,n,a):
        self.p=p
        self.N=N
        self.sN=sN
        self.q=q
        self.delt=delt
        self.n=n
        self.a=a
    
    def generate_A(self):
        self.A=module(random_matrix_A(self.sN,self.n,self.a),self.q)
        
        #этап query
    def query(self,index):
        if(index>N+1):
            print('Index is out of range!')
            return 0
        self.A=module(random_matrix_A(self.sN,self.n,self.a),self.q)
        i_raw=(index+1)//self.sN
        i_col=index%self.sN
        s=random_numbers(self.n,self.q)
        e=gauss_gen(sN)
        u=np.array([0]*sN)
        u[i_col]=1
        c=module(np.matmul(self.A,s)+e+self.delt*u,self.q)
        return i_raw,s,c
    
        #этап recovery
    def recovery(self,i_raw, s, Hc, r):
        dd=r[i_raw]-np.dot(Hc[i_raw],s)%self.q
        d=round(dd/self.delt)
        return(d)

