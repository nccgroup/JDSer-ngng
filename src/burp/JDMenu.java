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
