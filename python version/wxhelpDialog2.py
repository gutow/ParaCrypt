# -*- coding: UTF-8 -*-
#
# generated by wxGlade 0.8.0b1 on Wed Jan 10 20:52:58 2018
#

import wx

# begin wxGlade: dependencies
# end wxGlade

# begin wxGlade: extracode
import wx.html2
import os
import sys
import wxParaCrypt
from wxParaCrypt import AppFrame
# end wxGlade


class helpDialog(wx.Dialog):
    def __init__(self, *args, **kwds):
        # begin wxGlade: helpDialog.__init__
        kwds["style"] = kwds.get("style", 0) | wx.CAPTION |wx.SYSTEM_MENU | wx.CLOSE_BOX | wx.RESIZE_BORDER
        wx.Dialog.__init__(self, *args, **kwds)
        self.HelpBackButton = wx.Button(self, wx.ID_ANY, "<")
        self.HelpForwardButton = wx.Button(self, wx.ID_ANY, ">")
        self.HelpURL = wx.TextCtrl(self, wx.ID_ANY, "", style=wx.HSCROLL | wx.TE_READONLY)
        self.helpView = wx.html2.WebView.New(self)
        helppath = os.path.join(self.Parent.resourcepath,"ParaCryptHelp/ParaCryptHelp.html")
        self.helpView.LoadURL("file://"+helppath)
        self.HelpURL.ChangeValue("file://"+helppath)
        
        self.Bind(wx.html2.EVT_WEBVIEW_LOADED,self.onURLLoaded,self.helpView)

        self.__set_properties()
        self.__do_layout()

        self.Bind(wx.EVT_BUTTON, self.onHelpBack, self.HelpBackButton)
        self.Bind(wx.EVT_BUTTON, self.onHelpForward, self.HelpForwardButton)
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: helpDialog.__set_properties
        self.SetTitle("ParaCrypt Help")
        self.SetSize((590, 427))
        self.HelpBackButton.SetMinSize((50, 27))
        self.HelpForwardButton.SetMinSize((50, 27))
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: helpDialog.__do_layout
        sizer_1 = wx.BoxSizer(wx.HORIZONTAL)
        grid_sizer_2 = wx.FlexGridSizer(2, 1, 0, 0)
        grid_sizer_3 = wx.FlexGridSizer(0, 3, 0, 0)
        grid_sizer_3.Add(self.HelpBackButton, 0, 0, 0)
        grid_sizer_3.Add(self.HelpForwardButton, 0, 0, 0)
        grid_sizer_3.Add(self.HelpURL, 0, wx.EXPAND, 0)
        grid_sizer_3.AddGrowableCol(2)
        grid_sizer_2.Add(grid_sizer_3, 1, wx.EXPAND, 0)
        grid_sizer_2.Add(self.helpView, 1, wx.EXPAND, 0)
        grid_sizer_2.AddGrowableRow(1)
        grid_sizer_2.AddGrowableCol(0)
        sizer_1.Add(grid_sizer_2, 1, wx.EXPAND, 0)
        self.SetSizer(sizer_1)
        self.Layout()
        self.Centre()
        # end wxGlade

    def onHelpBack(self, event):  # wxGlade: helpDialog.<event_handler>
        if(self.helpView.CanGoBack()):
            self.helpView.GoBack()
        event.Skip()

    def onHelpForward(self, event):  # wxGlade: helpDialog.<event_handler>
        if(self.helpView.CanGoForward()):
            self.helpView.GoForward()
        event.Skip()
        
    def onURLLoaded(self, event):
        newURL = event.GetURL()
        self.HelpURL.ChangeValue(newURL)
        event.Skip()

# end of class helpDialog
