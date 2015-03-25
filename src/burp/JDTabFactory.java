package burp;

/**
 * Created by John on 24/03/2015.
 */
public class JDTabFactory implements IMessageEditorTabFactory {
    private IBurpExtenderCallbacks m_callbacks;
    private IExtensionHelpers m_helpers;

    public JDTabFactory(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        m_callbacks = callbacks;
        m_helpers = helpers;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        JDTab amfDeserializerTab = new JDTab(controller, editable, m_callbacks, m_helpers);
        return amfDeserializerTab;
    }
}
