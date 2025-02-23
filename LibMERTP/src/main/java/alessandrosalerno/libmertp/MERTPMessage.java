package alessandrosalerno.libmertp;

import org.apache.commons.text.StringEscapeUtils;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class MERTPMessage {
    private final String messageType;
    private String payload;
    private final Map<String, Object> content;

    protected MERTPMessage(String messageType, String payload) {
        this.messageType = messageType;
        this.payload = payload;
        if (null == this.payload) {
            this.payload = "";
        }
        this.content = new HashMap<>();
    }

    protected MERTPMessage(String messageType) {
        this(messageType, null);
    }

    public void addHeader(String key, Object value) {
        this.content.put(key, StringEscapeUtils.escapeJava(new String(value.toString().getBytes(),
                                                                        StandardCharsets.UTF_8)));
    }

    public String getHeader(String key) {
        return StringEscapeUtils.unescapeJava(this.content.get(key).toString());
    }

    public String getMessageType() {
        return this.messageType;
    }

    public String toProtocolMessage() {
        StringBuilder ret = new StringBuilder(this.messageType);

        for (String key : this.content.keySet()) {
            ret.append("\n").append(key).append(":").append(this.content.get(key));
        }

        if (!this.payload.isEmpty()) {
            ret.append("\n\n").append(this.payload);
        }

        return ret.toString();
    }

    public boolean isOfType(String messageType) {
        return this.messageType.equals(messageType);
    }

    public String getPayload() {
        return this.payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    @Override
    public String toString() {
        return this.toProtocolMessage();
    }
}
