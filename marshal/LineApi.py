# -*- coding: utf-8 -*-
from .Api import Poll, Talk, channel, call, shop
from akad.ttypes import *
import requests, tempfile, random, shutil, json, unicodedata, base64

def def_callback(str):
    print(str)

class LINE:

  mid = None
  authToken = None
  cert = None
  channel_access_token = None
  token = None
  obs_token = None
  refresh_token = None


  def __init__(self):
    Config.__init__(self)
    self.Talk = Talk()
    self._session = requests.session()

  def login(self, mail=None, passwd=None, cert=None, token=None, qr=False, callback=None, www=False):
    if callback is None:
      callback = def_callback
    resp = self.__validate(mail,passwd,cert,token,qr,www)
    if resp == 1:
      self.Talk.login(mail, passwd)
    elif resp == 2:
      self.Talk.login(mail, passwd, cert)
    elif resp == 3:
      self.Talk.TokenLogin(token)
    elif resp == 4:
      self.Talk.qrLogin()
    elif resp == 5:
      self.Talk.qrLogin2(callback)
    else:
      raise Exception("invalid arguments")

    self.authToken = self.Talk.authToken
    self.cert = self.Talk.cert
    self.headers = self.Talk.headers
    self.Poll = Poll(self.authToken)
    self.mid = self.Talk.client.getProfile().mid
    self.channel = channel.Channel(self.authToken,self.mid)
    self.channel.login()

    self.channel_access_token = self.channel.channel_access_token
    self.token = self.channel.token
    self.obs_token = self.channel.obs_token
    self.refresh_token = self.channel.refresh_token
    self.call = call.Call(self.authToken)
    
  def obs64(self, url):
    hasil = base64.b64encode(url.encode())
    return hasil.decode('utf-8')
    
  """User"""

  def getProfile(self):
    return self.Talk.client.getProfile()

  def getSettings(self):
    return self.Talk.client.getSettings()

  def getUserTicket(self):
    return self.Talk.client.getUserTicket()
  
  def reissueUserTicket(self, expirationTime, maxUseCount):
    return self.Talk.client.reissueUserTicket(expirationTime, maxUseCount)

  def updateProfile(self, profileObject):
    return self.Talk.client.updateProfile(0, profileObject)

  def updateSettings(self, settingObject):
    return self.Talk.client.updateSettings(0, settingObject)


  """Announcements"""
  def getChatRoomAnnouncementsBulk(self, chatRoomMids):
    return self.Talk.client.getChatRoomAnnouncementsBulk(chatRoomMids)

  def getChatRoomAnnouncements(self, chatRoomMids):
    return self.Talk.client.getChatRoomAnnouncements(chatRoomMids)

  def createChatRoomAnnouncement(self, chatRoomMid, _type, contents):
    return self.Talk.client.createChatRoomAnnouncement(0, chatRoomMid, _type, contents)

  def removeChatRoomAnnouncement(self, chatRoomMid, announcementSeq):
    return self.Talk.client.createChatRoomAnnouncement(0, chatRoomMid, announcementSeq)
  
  def getLastAnnouncementIndex(self):
    return self.Talk.client.getLastAnnouncementIndex()

  """Operation"""

  def fetchOperation(self, revision, count):
        return self.Poll.client.fetchOperations(revision, count)

  def fetchOps(self, rev, count):
        return self.Poll.client.fetchOps(rev, count, 0, 0)

  def getLastOpRevision(self):
        return self.Talk.client.getLastOpRevision()

  def stream(self):
        return self.Poll.stream()

  """CONTENT"""

  def post_content(self, url, data=None,files=None):
        return self._session.post(url,headers=self.headers,data=data,files=files)

  def get_content(self, url, headers=None):
        return self._session.get(url,headers=self.headers,stream=True)

  def downloadCOntent(self,url):
      path = '%s/LineZX-%i.data' % (tempfile.gettempdir(),random.randint(0,9))

      r = self.get_content(url)
      if r.status_code == 200:
          with open(path,'w') as f:
              shutil.copyfileobj(r.raw,f)    
          return path
      else:
          raise Exception('Download image failure.')

  """Message"""

  def downloadObjMsg(self,messageId):
    path = '%s/LineZX-%i.data' % (tempfile.gettempdir(),random.randint(0,9))
    url = self.LINE_OBS_DOMAIN + '/talk/m/download.nhn?oid=' + messageId
    r = self.get_content(url)
    if r.status_code == 200:
      with open(path,'w') as f:
         shutil.copyfileobj(r.raw,f)
      return path
    else:
      raise Exception('Download object failure.')

  def unsendMessage(self, messageId):
        return self.Talk.client.unsendMessage(0,messageId)

  def sendMessage(self, messageObject):
        return self.Talk.client.sendMessage(0,messageObject)

  def sendSticker(self, Tomid, packageId, stickerId):
        msg = Message()
        msg.contentMetadata = {
            'STKVER': '100',
            'STKPKGID': packageId,
            'STKID': stickerId
        }
        msg.contentType = 7
        msg.to = Tomid
        msg.text = ''
        return self.Talk.client.sendMessage(0, msg)

  def sendContact(self, Tomid, mid):
        msg = Message()
        msg.contentMetadata = {'mid': mid}
        msg.to = Tomid
        msg.text = ''
        msg.contentType = 13
        return self.Talk.client.sendMessage(0, msg)

  def sendText(self, Tomid, text):
        msg = Message()
        msg.to = Tomid
        msg.text = text

        return self.Talk.client.sendMessage(0, msg)

  def sendImage(self, to_, path):
        M = Message(to=to_, text=None, contentType = 1)
        M.contentMetadata = None
        M.contentPreview = None
        M2 = self.Talk.client.sendMessage(0,M)
        M_id = M2.id
        files = {
            'file': open(path, 'rb'),
        }
        params = {
            'name': 'media',
            'oid': M_id,
            'size': len(open(path, 'rb').read()),
            'type': 'image',
            'ver': '1.0',
        }
        data = {
            'params': json.dumps(params)
        }
        r = self.post_content(self.LINE_OBS_DOMAIN + '/talk/m/upload.nhn', data=data, files=files)
        if r.status_code != 201:
            raise Exception('Upload image failure.')
        #r.content
        return True

  def sendImageWithURL(self, to_, url):
      path = self.downloadCOntent(url)
      try:
          self.sendImage(to_,path)
      except Exception as e:
          raise e

  def sendVideo(self, to_, path):
        M = Message(to=to_, text=None, contentType = 2)
        M.contentMetadata = {'VIDLEN': '60000','DURATION': '60000'}
        M.contentPreview = None
        M2 = self.Talk.client.sendMessage(0,M)
        M_id = M2.id
        files = {
            'file': open(path, 'rb'),
        }
        params = {
            'name': 'media',
            'oid': M_id,
            'size': len(open(path, 'rb').read()),
            'type': 'video',
            'ver': '1.0',
        }
        data = {
            'params': json.dumps(params)
        }
        r = self.post_content(self.LINE_OBS_DOMAIN + '/talk/m/upload.nhn', data=data, files=files)
        if r.status_code != 201:
            raise Exception('Upload video failure.')
        #r.content
        return True

  def sendVideoWithURL(self, to_, url):
      path = self.downloadCOntent(url)
      try:
          self.sendVideo(to_,path)
      except Exception as e:
          raise e

  def sendEvent(self, messageObject):
        return self._client.sendEvent(0, messageObject)

  def sendChatChecked(self, mid, lastMessageId):
        return self.Talk.client.sendChatChecked(0, mid, lastMessageId)

  def getMessageBoxCompactWrapUp(self, mid):
        return self.Talk.client.getMessageBoxCompactWrapUp(mid)

  def getMessageBoxCompactWrapUpList(self, start, messageBox):
        return self.Talk.client.getMessageBoxCompactWrapUpList(start, messageBox)

  def getRecentMessages(self, messageBox, count):
        return self.Talk.client.getRecentMessages(messageBox.id, count)

  def getMessageBox(self, channelId, messageboxId, lastMessagesCount):
        return self.Talk.client.getMessageBox(channelId, messageboxId, lastMessagesCount)

  def getMessageBoxList(self, channelId, lastMessagesCount):
        return self.Talk.client.getMessageBoxList(channelId, lastMessagesCount)

  def getMessageBoxListByStatus(self, channelId, lastMessagesCount, status):
        return self.Talk.client.getMessageBoxListByStatus(channelId, lastMessagesCount, status)

  def getMessageBoxWrapUp(self, mid):
        return self.Talk.client.getMessageBoxWrapUp(mid)

  def getMessageBoxWrapUpList(self, start, messageBoxCount):
        return self.Talk.client.getMessageBoxWrapUpList(start, messageBoxCount)

  """Contact"""


  def blockContact(self, mid):
        return self.Talk.client.blockContact(0, mid)


  def unblockContact(self, mid):
        return self.Talk.client.unblockContact(0, mid)


  def findAndAddContactsByMid(self, mid):
        return self.Talk.client.findAndAddContactsByMid(0, mid)


  def findAndAddContactsByMids(self, midlist):
        for i in midlist:
            self.Talk.client.findAndAddContactsByMid(0, i)

  def findAndAddContactsByUserid(self, userid):
        return self.Talk.client.findAndAddContactsByUserid(0, userid)

  def findContactsByUserid(self, userid):
        return self.Talk.client.findContactByUserid(userid)

  def findContactByTicket(self, ticketId):
        return self.Talk.client.findContactByUserTicket(ticketId)

  def getAllContactIds(self):
        return self.Talk.client.getAllContactIds()

  def getBlockedContactIds(self):
        return self.Talk.client.getBlockedContactIds()

  def getContact(self, mid):
        return self.Talk.client.getContact(mid)

  def getContacts(self, midlist):
        return self.Talk.client.getContacts(midlist)

  def getFavoriteMids(self):
        return self.Talk.client.getFavoriteMids()

  def getHiddenContactMids(self):
        return self.Talk.client.getHiddenContactMids()


  """Group"""

  def acceptGroupInvitation(self, groupId):
        return self.Talk.client.acceptGroupInvitation(0, groupId)

  def acceptGroupInvitationByTicket(self, groupId, ticketId):
        return self.Talk.client.acceptGroupInvitationByTicket(0, groupId, ticketId)

  def cancelGroupInvitation(self, groupId, contactIds):
        return self.Talk.client.cancelGroupInvitation(0, groupId, contactIds)

  def createGroup(self, name, midlist):
        return self.Talk.client.createGroup(0, name, midlist)

  def getGroupWithoutMembers(self, groupId):
        return self.Talk.client.getGroupWithoutMembers(groupId)

  def getGroup(self, groupId):
        return self.Talk.client.getGroup(groupId)

  def getGroups(self, groupIds):
        return self.Talk.client.getGroups(groupIds)
 
  def getGroupsV2(self, groupIds):
        return self.Talk.client.getGroupsV2(groupIds)

  def getGroupIdsInvited(self):
        return self.Talk.client.getGroupIdsInvited()

  def getGroupIdsJoined(self):
        return self.Talk.client.getGroupIdsJoined()

  def inviteIntoGroup(self, groupId, midlist):
        return self.Talk.client.inviteIntoGroup(0, groupId, midlist)

  def kickoutFromGroup(self, groupId, midlist):
        return self.Talk.client.kickoutFromGroup(0, groupId, midlist)

  def leaveGroup(self, groupId):
        return self.Talk.client.leaveGroup(0, groupId)

  def rejectGroupInvitation(self, groupId):
        return self.Talk.client.rejectGroupInvitation(0, groupId)

  def reissueGroupTicket(self, groupId):
        return self.Talk.client.reissueGroupTicket(groupId)

  def updateGroup(self, groupObject):
        return self.Talk.client.updateGroup(0, groupObject)
    
  def findGroupByTicket(self,ticketId):
        return self.Talk.client.findGroupByTicket(0,ticketId)

  """Room"""

  def createRoom(self, midlist):
    return self.Talk.client.createRoom(0, midlist)

  def getRoom(self, roomId):
    return self.Talk.client.getRoom(roomId)

  def inviteIntoRoom(self, roomId, midlist):
    return self.Talk.client.inviteIntoRoom(0, roomId, midlist)

  def leaveRoom(self, roomId):
    return self.Talk.client.leaveRoom(0, roomId)

  """TIMELINE"""

  def new_post(self, text):
    return self.channel.new_post(text)

  def like(self, mid, postid, likeType=1001):
    return self.channel.like(mid, postid, likeType)

  def comment(self, mid, postid, text):
    return self.channel.comment(mid, postid, text)

  def activity(self, limit=20):
    return self.channel.activity(limit)

  def getAlbum(self, gid):

      return self.channel.getAlbum(gid)
  def changeAlbumName(self, gid, name, albumId):
      return self.channel.changeAlbumName(gid, name, albumId)

  def deleteAlbum(self, gid, albumId):
      return self.channel.deleteAlbum(gid,albumId)

  def getNote(self,gid, commentLimit, likeLimit):
      return self.channel.getNote(gid, commentLimit, likeLimit)

  def getDetail(self,mid):
      return self.channel.getDetail(mid)

  def getHome(self,mid):
      return self.channel.getHome(mid)

  def createAlbum(self, gid, name):
      return self.channel.createAlbum(gid,name)

  def createAlbum2(self, gid, name, path):
      return self.channel.createAlbum(gid, name, path, oid)

  """Callservice"""

  def acquireCallRoute(self,to):
        return self.call.acquireCallRoute(to)

  def acquireGroupCallRoute(self, groupId, mediaType=MediaType.AUDIO):
        return self.call.acquireGroupCallRoute(groupId, mediaType)

  def getGroupCall(self, ChatMid):
        return self.call.getGroupCall(ChatMid)

  def inviteIntoGroupCall(self, chatId, contactIds=[], mediaType=MediaType.AUDIO):
        return self.call.inviteIntoGroupCall(chatId, contactIds, mediaType)
    
  """Shop Service"""
  
  def getProduct(self, packageID):
        return self.shop.getProduct(packageID)
    
  def getActivePurchases(self, start, size):
        return self.shop.getNewlyReleasedPackages(start, size)

  def getDownloads(self):
        return self.shop.getDownloads()

  def getCoinProducts(self, appStoreCode):
        return self.shop.getCoinProducts(appStoreCode)

  def getEventPackages(self, start, size):
        return self.shop.getEventPackages(start, size)

  def getPopularPackages(self, start, size):
        return self.shop.getPopularPackages(start, size)

  def notifyDownloaded(self, packageId):
        return self.shop.notifyDownloaded(packageId)

  def __validate(self, mail, passwd, cert, token, qr, www):
    if mail is not None and passwd is not None and cert is None:
      return 1
    elif mail is not None and passwd is not None and cert is not None:
      return 2
    elif token is not None:
      return 3
    elif qr is True:
      return 4
    elif www is True:
      return 6
    else:
      return 5

  def loginResult(self, callback=None):
    if callback is None:
      callback = def_callback

      prof = self.getProfile()

      print("[ LINE BOT ]")
      print("MID : " + prof.mid)
      print("NAME : " + prof.displayName)
      print("AuthToken :  " + self.authToken)
      print("Channel Token :  " + self.channel_access_token)
      print("Cert : " + self.cert if self.cert is not None else "")
