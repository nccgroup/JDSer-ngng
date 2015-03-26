/*
 * Copyright (c) John Murray, 2015.
 *
 *   This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU Affero General Public License as
 *     published by the Free Software Foundation, either version 3 of the
 *     License, or (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU Affero General Public License for more details.
 *
 *     You should have received a copy of the GNU Affero General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package burp;

import javax.swing.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/* Created by John on 24/03/2015.*/


public class JDMenu implements IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public JDMenu(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        JMenuItem sendJDToIntruderMenu = new JMenuItem("Send Deserialized Java to Intruder");


        sendJDToIntruderMenu.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent arg0) {

            }

            @Override
            public void mouseEntered(MouseEvent arg0) {
            }

            @Override
            public void mouseExited(MouseEvent arg0) {
            }

            @Override
            public void mousePressed(MouseEvent arg0) {
                IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
                for (IHttpRequestResponse iReqResp : selectedMessages) {
                    IHttpService httpService = iReqResp.getHttpService();

                    try {
                        //get the XML body
                        byte[] XMLBody = JDUtils.toXML(iReqResp.getRequest(), helpers);

                        //add the magic header so we know to reserialize before sending out
                        List<String> headers = helpers.analyzeRequest(iReqResp.getRequest()).getHeaders();
                        headers.add(JDUtils.SERIALIZEHEADER);

                        //replace the existing body with the XML and send to intruder
                        callbacks.sendToIntruder(httpService.getHost(), httpService.getPort(), (httpService.getProtocol().equals("https") ? true : false),
                                helpers.buildHttpMessage(headers, XMLBody));


                    }
                    catch (IOException | ClassNotFoundException ex)
                    {
                        System.out.println("Error sending item to intruder " + ex.fillInStackTrace());
                    }



                }
            }

            @Override
            public void mouseReleased(MouseEvent arg0) {
            }
        });


        List<JMenuItem> menus = new ArrayList();
        menus.add(sendJDToIntruderMenu);
        return menus;
    }

}
