package ca.yorku.eecs.dnslookup;

import java.net.InetAddress;

public interface DNSProcessListener {

    void beforeSendingQuery(DNSQuestion question, InetAddress server, int transactionID);

    void receivedResponse(int receivedTransactionId, boolean authoritative, int errorCode);

    void beforeProcessingAnswerSection(int num_answers);
    void beforeProcessingNameserversSection(int num_nameservers);
    void beforeProcessingAdditionalRecordsSection(int num_additional);

    void receivedResourceRecord(ResourceRecord record, int typeCode, int classCode);
}
