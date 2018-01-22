#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import wx
import wx.adv
#import wxhelpDialog
import wxhelpDialog2 as wxhelpDialog
import gettext
import sys
import os as os
from randomizekey import *
from encryptutil import *
from decryptutil import *
from ParaCrypt_Glade_GUI import ParaCryptFrame

class AppFrame(ParaCryptFrame):
    
    def __init__(self, *args, **kwds):
        ParaCryptFrame.__init__(self, *args, **kwds)
        self.keypath=''
        self.KeyFilePath.ChangeValue(self.keypath)
        self.toencryptpath=''
        self.toEncryptPath.ChangeValue(self.toencryptpath)
        self.passwd=''
        self.encryptPassword.ChangeValue(self.passwd)
        #sys.stdout=self.procOutText
        #sys.stderr=self.procOutText

    def onQuit(self, event):  
        #print("Event handler 'onQuit' not implemented!")
        exit()
        event.Skip()
        
    def onAbout(self, event):  # wxGlade: ParaCryptFrame.<event_handler>
        info=wx.adv.AboutDialogInfo()
        #get the icon
        iconpath=os.path.join(sys.path[0],"ParaCryptArt/ParaCryptIcon256.png")
        tempicon=wx.Icon(iconpath)
        info.SetIcon(tempicon)
        info.SetName("ParaCrypt\n(Paranoid Encrypt)")
        #get version, authors and license info from Version.xml
        v = open(os.path.join(sys.path[0],"Version.xml"),"r")
        version=""
        versionlong=""
        license=""
        developers=[]
        line=v.readline()
        while line:
            #parse lines to get data
            pos1 = line.find("<version>")
            if (pos1 >=0):
                pos2 = line.find("</version>")
                version=line[(pos1+9):pos2]
            pos1= line.find("<version_long>")
            if (pos1 >=0):
                pos2=line.find("</version_long>")
                versionlong = line[(pos1+15):pos2]
            pos1=line.find("<author>")
            if (pos1 >= 0):
                pos2=line.find("</author>")
                developers.append(line[(pos1+8):pos2])
            pos1=line.find("<license>")
            if (pos1 >= 0):
                pos2=line.find("</license>")
                license=line[(pos1+9):pos2]
            line=v.readline()
        v.close()
        info.SetVersion(version,versionlong)
        info.SetDevelopers(developers)
        info.SetCopyright(_("(C) 2018 Jonathan Gutow"))
        wx.adv.AboutBox(info,parent=self)
        event.Skip()
        
    def onHelp(self, event):  # wxGlade: ParaCryptFrame.<event_handler>
        help=wxhelpDialog.helpDialog(self)
        help.Show()
        event.Skip()
        
    def onChooseKey(self, event):  
        with wx.FileDialog(self, _("Select the Key File"), wildcard="",
            style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST | 
            wx.FD_CHANGE_DIR) as fileDialog:

            if fileDialog.ShowModal() == wx.ID_CANCEL:
                event.Skip()     # the user changed their mind

        # display the path.
            self.KeyFilePath.ChangeValue(fileDialog.GetPath())
        event.Skip()

    def onChooseToEncrypt(self, event):  
        with wx.FileDialog(self, _("Select the File to Encrypt or Decrypt:"), wildcard="",
            style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST | 
            wx.FD_CHANGE_DIR) as fileDialog:

            if fileDialog.ShowModal() == wx.ID_CANCEL:
                event.Skip()     # the user changed their mind

        # display the path.
            self.toEncryptPath.ChangeValue(fileDialog.GetPath())
        event.Skip()
        
    def onEncrypt(self, event):
        errFound = self._checkFilesPasswd(self.KeyFilePath.GetValue(),self.toEncryptPath.GetValue(),self.encryptPassword.GetValue())
        if (errFound):
            event.Skip()
        else:
            # open save dialog to pick location to save the encrypted file.
            with wx.FileDialog(self, _("Save Encrypted File As..."), wildcard="",
                style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT | 
                wx.FD_CHANGE_DIR) as fileDialog:

                if fileDialog.ShowModal() == wx.ID_CANCEL:
                    event.Skip()     # the user changed their mind
                    return()
                    
                savePath=fileDialog.GetPath()
                rawName=os.path.basename(self.toencryptpath)
                #print('savePath='+savePath+' \nrawName='+rawName)
            
            # encrypt and save the file.
            wait = wx.GenericProgressDialog("Processing",message="",maximum=8)
            wait.Update(1,"Processing...(Please Wait)")
            # 1) Randomize the key file using the password.
            wait.Update(2, "Randomizing key file...")
            rawkey=open(self.keypath,'rb')
            rndkey=randomizefile(rawkey, self.passwd)
            rawkey.close()
            # 2) Encrypt the file using the temporary randomized key file.
            wait.Update(4, "Encrypting file...")
            toencryptfile=open(self.toencryptpath,'rb')
            encrypted=encryptfile(toencryptfile,rawName,rndkey)
            toencryptfile.close()
            tempPath=os.path.realpath(encrypted.name)
            encrypted.close()
            # 3) Save the encrypted file to the requested name.
            wait.Update(6, "Saving encrypted file...")
            os.rename(tempPath,savePath)
            # 4) Securely delete the randomized key file.
            wait.Update(7, "Securely erasing randomized key file...")
            result=secureerasefile(rndkey)
            wait.Update(8, "Done.")
            print ("Encryption Completed.")
            del wait
            event.Skip()

    def onDecrypt(self, event):
        errFound = self._checkFilesPasswd(self.KeyFilePath.GetValue(),self.toEncryptPath.GetValue(),self.encryptPassword.GetValue())
        if (errFound):
            event.Skip()
        else:
            # open save dialog to pick location to save the decrypted file.
            with wx.DirDialog(self, _("Select Directory to Save Decrypted File in:"),"",
                style= wx.DD_DEFAULT_STYLE) as dirDialog:

                if dirDialog.ShowModal() == wx.ID_CANCEL:
                    event.Skip()     # the user changed their mind
                    return()
                
                savePath=dirDialog.GetPath()
            # decrypt and save the file.
            wait = wx.GenericProgressDialog("Processing",message="",maximum=8)
            wait.Update(1,"Processing...(Please Wait)")
            # 1) Randomize the key file using the password.
            wait.Update(2, "Randomizing key file...")
            rawkey=open(self.keypath,'rb')
            rndkey=randomizefile(rawkey, self.passwd)
            rawkey.close()
            # 2) Decrypt the file using the temporary randomized key file.
            wait.Update(5, "Decrypting file...")
            todecryptfile=open(self.toencryptpath,'rb')
            result = decryptfile(savePath,todecryptfile,rndkey)
            todecryptfile.close()
            wait.Update(7,"Securely erasing randomized key file...")
            result=secureerasefile(rndkey)
            wait.Update(8, "Done")
            print("Decryption completed.")
            del wait
            event.Skip()

# Private Utility functions

    def _checkFilesPasswd(self,keypath,filepath,passwd):
        #Check for valid files and password
        errDialogText = ''
        errFound=False
        if (os.path.isfile(keypath)):
            self.keypath=keypath
        else:
            errFound=True
            errDialogText=_("Key File is not a valid file.\nPlease choose another.")
        if (os.path.isfile(filepath)):
            self.toencryptpath=filepath
        else:
            errFound=True
            errDialogText=_("The file to encrypt or decrypt is not a valid file.\nPlease choose another.")
        if (len(passwd)>=8):
            self.passwd=passwd
        else:
            errFound=True
            errDialogText=_("Your password should be at least 8 characters.\nPlease choose another.")
        if (errFound):
            #pop up error dialog then return to GUI
            with wx.MessageDialog(self,errDialogText,_("Error"),style=wx.OK|wx.ICON_ERROR) as errDialog:
                if errDialog.ShowModal()==wx.OK:
                    return(errFound)
        return(errFound)
        
#App class
class ParaCrypt(wx.App):
    def OnInit(self):
        frame_1 = AppFrame(None, wx.ID_ANY, "")
        self.RedirectStdio(filename=None)
        self.SetOutputWindowAttributes(title='ParaCrypt Messages', pos=None, size=(500,100))
        self.SetTopWindow(frame_1)
        frame_1.Show()
        return True

# end of class ParaCrypt

if __name__ == "__main__":
    gettext.install("ParaCrypt") # replace with the appropriate catalog name

    ParaCrypt = ParaCrypt(0)
    ParaCrypt.MainLoop()
