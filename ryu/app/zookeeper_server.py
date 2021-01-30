#*-* coding:utf-8 -*-
from kazoo.client import KazooClient


class Zookeeper_Server:

    def __init__(self,host,port):
        self.zk = KazooClient(hosts=host+':'+port)
        self.zk.start()

    #读取zookeeper节点
    def get_zk_node(self,nodePath):
        #获取节点下的所有子节点
        zkNode = self.zk.get_children(nodePath,watch=self.watches())
        #获取节点的值
        # zkNodeValue = self.zk.get(nodePath,watch=self.watches())
        zkNodeValue = self.zk.get(nodePath)

        # self.zk.stop()
        return zkNode,zkNodeValue

    #设置zookeeper节点
    def set_zk_node(self,nodePath,setNodeValue):
        #设置节点的值
        self.zk.set(nodePath,setNodeValue)

        # self.zk.stop()

    #删除zookeeper节点
    def del_zk_node(self,nodePath):
        #recursive为True则删除此节点和所有子节点
        #recursive为False则当节点有子节点，则抛出NotEmptyError异常
        self.zk.delete(nodePath,recursive=True)

        # self.zk.stop()

    #创建zookeeper节点
    def create_zk_node(self,nodePath,nodeValue):
        #sequence:若为 True 则在你创建节点名后面增加10位数字
        #makepath：  若为 False 父节点不存在时抛 NoNodeError。若为 True 父节点不存在则创建父节点。默认 False
        self.zk.create(nodePath,bytes(nodeValue),sequence=False,makepath=True)

        # self.zk.stop()

    #判断节点是否存在
    def jude_node_exists(self,nodePath):
        if self.zk.exists(nodePath):
            # self.zk.stop()
            return True
        else:
            # self.zk.stop()
            return False

    #监听事件(只能设置在节点的读取上)
    def watches(self):
        pass

