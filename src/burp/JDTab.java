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

/**
 * Created by John on 24/03/2015.
 */

import java.awt.*;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

class JDTab implements IMessageEditorTab
{
    private boolean editable;
    private ITextEditor txtInput;
    private byte[] currentMessage;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public JDTab(IMessageEditorController controller, boolean editable, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.editable = editable;
        this.callbacks = callbacks;
        this.helpers = helpers;
        // create an instance of Burp's text editor, to display our deserialized
        // data
        txtInput = callbacks.createTextEditor();
        txtInput.setEditable(editable);
    }

    //
    // implement IMessageEditorTab
    //

    @Override
    public String getTabCaption() {
        return "Deserialized Java";
    }

    @Override
    public Component getUiComponent() {
        return txtInput.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return  JDUtils.isJD(content, this.helpers);
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest)
    {
        if (content == null) {
            // clear our display
            txtInput.setText(null);
            txtInput.setEditable(false);

        } else {

            try {
                //serialize to java and set the text
                txtInput.setText(JDUtils.toXML(content, helpers));
            } catch (IOException | ClassNotFoundException ex) {
                Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
                txtInput.setText(helpers.stringToBytes("Unable to deserailize, most likely you have not loaded the corresponding JAR\n\n" + ex.fillInStackTrace()));
            }
            txtInput.setEditable(editable);
        }

        // remember the displayed content
        currentMessage = content;
    }

    @Override
    public byte[] getMessage() {

        // determine whether the user modified the deserialized data
        if (txtInput.isTextModified()) {

            //if the input has changed, serialize back to java
            byte[] newBody = JDUtils.fromXML(txtInput.getText(), helpers);
            return helpers.buildHttpMessage(helpers.analyzeRequest(currentMessage).getHeaders(), newBody);
        } else {
            return currentMessage;
        }
    }

    @Override
    public boolean isModified() {
        if (txtInput.isTextModified()) {
            //if the XML is modified, reserialize it to allow us to send on
            getMessage();
        }
        return txtInput.isTextModified();
    }

    @Override
    public byte[] getSelectedData() {
        return txtInput.getSelectedText();
    }
}