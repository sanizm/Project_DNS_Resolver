package ca.yorku.eecs.dnslookup;


import java.io.Closeable;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.IntStream;

@SuppressWarnings("unused")
public class DNSLookupProcess implements Closeable {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL_NS = 10;
    private static final int MAX_QUERY_ATTEMPTS = 3;
    protected static final int SO_TIMEOUT = 5000;

    private final DNSCache cache = DNSCache.getInstance();
    private final Random random = new SecureRandom();
    private final DNSProcessListener listener;
    private final DatagramSocket socket;
    private InetAddress nameServer;
    private ByteBuffer query;
    private ByteBuffer response;

    /**
     * Creates a new lookup service. Also initializes the datagram socket object with a default timeout.
     *
     * @param nameServer The nameserver to be used initially. If set to null, "root" or "random", will choose a random
     *                   pre-determined root nameserver.
     * @param listener   A DNSProcessListener listener object with methods to be called at key events in the query
     *                   processing.
     * @throws SocketException      If a DatagramSocket cannot be created.
     * @throws UnknownHostException If the nameserver is not a valid server.
     */
    public DNSLookupProcess(String nameServer, DNSProcessListener listener) throws SocketException, UnknownHostException {
        this.listener = listener;
        socket = new DatagramSocket();
        socket.setSoTimeout(SO_TIMEOUT);
        this.setNameServer(nameServer);
    }

    /**
     * Returns the nameserver currently being used for queries.
     *
     * @return The string representation of the nameserver IP address.
     */
    public String getNameServer() {
        return this.nameServer.getHostAddress();
    }

    /**
     * Updates the nameserver to be used in all future queries.
     *
     * @param nameServer The nameserver to be used initially. If set to null, "root" or "random", will choose a random
     *                   pre-determined root nameserver.
     * @throws UnknownHostException If the nameserver is not a valid server.
     */
    public void setNameServer(String nameServer) throws UnknownHostException {

        // If none provided, choose a random root nameserver
        if (nameServer == null || nameServer.equalsIgnoreCase("random") || nameServer.equalsIgnoreCase("root")) {
            List<ResourceRecord> rootNameServers = cache.getCachedResults(DNSCache.rootQuestion, false);
            nameServer = rootNameServers.get(0).getTextResult();
        }
        this.nameServer = InetAddress.getByName(nameServer);
    }

    /**
     * Closes the lookup service and related sockets and resources.
     */
    public void close() {
        socket.close();
    }

    /**
     * Finds all the result for a specific node. If there are valid (not expired) results in the cache, uses these
     * results, otherwise queries the nameserver for new records. If there are CNAME records associated to the question,
     * they are included in the results as CNAME records (i.e., not queried further).
     *
     * @param question Host and record type to be used for search.
     * @return A (possibly empty) set of resource records corresponding to the specific query requested.
     */
    public Collection<ResourceRecord> getDirectResults(DNSQuestion question) {

        Collection<ResourceRecord> results = cache.getCachedResults(question, true);
        if (results.isEmpty()) {
            iterativeQuery(question, nameServer);
            results = cache.getCachedResults(question, true);
        }
        return results;
    }

    /**
     * Finds all the result for a specific node. If there are valid (not expired) results in the cache, uses these
     * results, otherwise queries the nameserver for new records. If there are CNAME records associated to the question,
     * they are retrieved recursively for new records of the same type, and the returning set will contain both the
     * CNAME record and the resulting addresses.
     *
     * @param question             Host and record type to be used for search.
     * @param maxIndirectionLevels Number of CNAME indirection levels to support.
     * @return A set of resource records corresponding to the specific query requested.
     * @throws CnameIndirectionLimitException If the number CNAME redirection levels exceeds the value set in
     *                                        maxIndirectionLevels.
     */
    public Collection<ResourceRecord> getRecursiveResults(DNSQuestion question, int maxIndirectionLevels) throws CnameIndirectionLimitException {

        if (maxIndirectionLevels < 0) throw new CnameIndirectionLimitException();

        Collection<ResourceRecord> directResults = getDirectResults(question);
        if (directResults.isEmpty() || question.getRecordType() == RecordType.CNAME) return directResults;

        List<ResourceRecord> newResults = new ArrayList<>();
        for (ResourceRecord record : directResults) {
            newResults.add(record);
            if (record.getRecordType() == RecordType.CNAME) {
                newResults.addAll(getRecursiveResults(new DNSQuestion(record.getTextResult(), question.getRecordType(), question.getRecordClass()), maxIndirectionLevels - 1));
            }
        }
        return newResults;
    }

    /**
     * Retrieves DNS results from a specified DNS server using the iterative mode. After an individual query is sent and
     * its response is received (or times out), checks if an answer for the specified host exists. Resulting values
     * (including answers, nameservers and additional information provided by the nameserver) are added to the cache.
     * <p>
     * If after the first query an answer exists to the original question (either with the same record type or an
     * equivalent CNAME record), the function returns with no further actions. If there is no answer after the first
     * query but the response returns at least one nameserver, a follow-up query for the same question must be done to
     * another nameserver.
     * <p>
     * Note that nameservers returned by the response contain text records linking to the host names of these servers.
     * If at least one nameserver provided by the response to the first query has a known IP address (either from this
     * query or from a previous query), it must be used first, otherwise additional queries are required to obtain the
     * IP address of the nameserver before it is queried. Only one nameserver must be contacted for the follow-up
     * query.
     * @param question      Host name and record type/class to be used for the query.
     * @param serverAddress Address of the server to be used for the first query.
     */
    protected void iterativeQuery(DNSQuestion question, InetAddress serverAddress){

        Set<ResourceRecord> NS = this.individualQueryProcess(question,serverAddress);
        Set<ResourceRecord> NS_COPY = NS;
        List<ResourceRecord> answerList = this.cache.getCachedResults(question, true);
        try {
            while (NS_COPY.iterator().hasNext()) {
                ResourceRecord RR = NS_COPY.iterator().next();
                while (answerList.size() == 0) {

                        InetAddress IA = InetAddress.getByName(RR.getTextResult());
                        NS = this.individualQueryProcess(question, IA);
                    answerList = this.cache.getCachedResults(question, true);
                        if(answerList.size() != 0) break;
                    if(NS.size() != 0) {
                        RR = NS.iterator().next();
                    }else
                        break;
                }
                answerList = this.cache.getCachedResults(question,true);
                if(answerList.size() != 0)
                    break;
            }


        }catch (Exception ignored){

        }
    }

    /**
     * Handles the process of sending an individual DNS query to a single question. Builds and sends the query (request)
     * message, then receives and parses the response. Received responses that do not match the requested transaction ID
     * are ignored. If no response is received after SO_TIMEOUT milliseconds, the request is sent again, with the same
     * transaction ID. The query should be sent at most MAX_QUERY_ATTEMPTS times, after which the function should return
     * without changing any values. If a response is received, all of its records are added to the cache.
     * <p>
     * The method listener.beforeSendingQuery() must be called every time a new query message is about to be sent.
     *
     * @param question      Host name and record type/class to be used for the query.
     * @param serverAddress Address of the server to be used for the query.
     * @return If no response is received, returns null. Otherwise, returns a set of resource records for all
     * nameservers received in the response. Only records found in the nameserver section of the response are included,
     * and only those whose record type is NS. If a response is received but there are no nameservers, returns an empty
     * set.
     */
    protected Set<ResourceRecord> individualQueryProcess(DNSQuestion question, InetAddress serverAddress) {
        Set<ResourceRecord> RR = null;
                this.query = ByteBuffer.wrap(new byte[512]);
                boolean recievedRightResponse = false;
                int attempts = 1;
                int Transaction_ID = buildQuery(this.query, question);
                byte[] queryToSend = new byte[this.query.position()];
                byte[] responseToReceive = new byte[512];
                this.query = this.query.flip();
                this.query.get(queryToSend);
        DatagramPacket packet = new DatagramPacket(queryToSend, queryToSend.length, serverAddress, DEFAULT_DNS_PORT);
        DatagramPacket responsePacket = new DatagramPacket(responseToReceive, responseToReceive.length);

            try {
                    // calling beforeSendingQuery() before sending new query message
                    this.listener.beforeSendingQuery(question, serverAddress, Transaction_ID);
                    this.socket.send(packet);
                long start = System.currentTimeMillis();
                long end = start + 5*1000;
                while (System.currentTimeMillis() < end) {
                    this.socket.receive(responsePacket);
                    responseToReceive = responsePacket.getData();
                    this.response = ByteBuffer.wrap(responseToReceive);
                    short responseTransaction_ID = (short) ((responseToReceive[0] << 8) | (responseToReceive[1] & 0xFF));
                    boolean isResponse = (responseToReceive[2] & 0b10000000) == 0b10000000;
                    if (Transaction_ID == responseTransaction_ID && isResponse) {
                        RR = this.processResponse(this.response);
                        break;
                    }
                }

            }catch (Exception e){
                try {
                    this.listener.beforeSendingQuery(question, serverAddress, Transaction_ID);
                    this.socket.send(packet);
                    long start = System.currentTimeMillis();
                long end = start + 5*1000;
                while (System.currentTimeMillis() < end) {
                    this.socket.receive(responsePacket);
                    responseToReceive = responsePacket.getData();
                    this.response = ByteBuffer.wrap(responseToReceive);
                    short responseTransaction_ID = (short) ((responseToReceive[0] << 8) | (responseToReceive[1] & 0xFF));
                    boolean isResponse = (responseToReceive[2] & 0b10000000) == 0b10000000;
                    if (Transaction_ID == responseTransaction_ID && isResponse) {
                        RR = this.processResponse(this.response);
                        break;
                    }
                }
                }catch(Exception f) {
                    try {
                        this.listener.beforeSendingQuery(question, serverAddress, Transaction_ID);
                        this.socket.send(packet);
                        long start = System.currentTimeMillis();
                        long end = start + 5*1000;
                        while (System.currentTimeMillis() < end) {
                            this.socket.receive(responsePacket);
                            responseToReceive = responsePacket.getData();
                            this.response = ByteBuffer.wrap(responseToReceive);
                            short responseTransaction_ID = (short) ((responseToReceive[0] << 8) | (responseToReceive[1] & 0xFF));
                            boolean isResponse = (responseToReceive[2] & 0b10000000) == 0b10000000;
                            if (Transaction_ID == responseTransaction_ID && isResponse) {
                                RR = this.processResponse(this.response);
                                break;
                            }
                        }
                    }catch(Exception ignored) {

                    }
                }
            }
        return RR;
    }

    /**
     * Fills a ByteBuffer object with the contents of a DNS query. The buffer must be updated from the start (position
     * 0). A random transaction ID must also be generated and filled in the corresponding part of the query. The query
     * must be built as an iterative (non-recursive) request for a regular query with a single question. When the
     * function returns, the buffer's position (`queryBuffer.position()`) must be equivalent to the size of the query
     * data.
     *
     * @param queryBuffer The ByteBuffer object where the query will be saved.
     * @param question    Host name and record type/class to be used for the query.
     * @return The transaction ID used for the query.
     */
    protected int buildQuery(ByteBuffer queryBuffer, DNSQuestion question) {
        short Transaction_ID = (short) (1025 + this.random.nextInt(Short.MAX_VALUE - 1025));
        short QROpcodeAATCRDRAZRCODE = 0;
        short QDCOUNT = 1;
        short ANCOUNT = 0;
        short NSCOUNT = 0;
        short ARCOUNT = 0;
        short QTYPE =  (short) question.getRecordType().getCode();
        short QCLASS = (short) question.getRecordClass().getCode();
        queryBuffer.putShort(Transaction_ID)
                .putShort(QROpcodeAATCRDRAZRCODE)
                .putShort(QDCOUNT)
                .putShort(ANCOUNT)
                .putShort(NSCOUNT)
                .putShort(ARCOUNT)
                ;
        addFQDN(queryBuffer,question);
        queryBuffer.putShort(QTYPE).putShort(QCLASS);

        return Transaction_ID;
    }

    /**
     * This method converts the given representation of the domain name from string to bytes in order to build a query
     * and store it in the query buffer.
     * @param queryBuffer - the bytebuffer that needs to be filled with byte values of the domain name
     * @param question - the question that contains the name of the domain. (hostName, Type and recordClass).
     */

    private void addFQDN(ByteBuffer queryBuffer, DNSQuestion question) {
        String[] labels = question.getHostName().split("\\.");
        for (String label : labels) {
            byte[] labelSize = new byte[]{(byte) label.length()};
            byte[] labelInBytes = label.getBytes(StandardCharsets.UTF_8);
            byte[] result = new byte[labelSize.length + labelInBytes.length];
            System.arraycopy(labelSize, 0, result, 0, labelSize.length);
            System.arraycopy(labelInBytes, 0, result, labelSize.length, labelInBytes.length);
            queryBuffer.put(result);
        }
        byte terminationFQDN = 0;
        queryBuffer.put(terminationFQDN);
    }

    /**
     * Parses and processes a response received by a nameserver. Adds all resource records found in the response message
     * to the cache. Calls methods in the listener object at appropriate points of the processing sequence. Must be able
     * to properly parse records of the types: A, AAAA, NS, CNAME and MX (the priority field for MX may be ignored). Any
     * other unsupported record type must create a record object with the data represented as a hex string (see method
     * byteArrayToHexString).
     *
     * @param responseBuffer The ByteBuffer associated to the response received from the server.
     * @return A set of resource records for all nameservers received in the response. Only records found in the
     * nameserver section of the response are included, and only those whose record type is NS. If there are no
     * nameservers, returns an empty set.
     */
    protected Set<ResourceRecord> processResponse(ByteBuffer responseBuffer) {
            Set<ResourceRecord> NS_RESULT = new LinkedHashSet<>();
            short TRANSACTION_ID = responseBuffer.getShort(0);
            short QROpcodeAATCRDRAZRCODE = responseBuffer.getShort(2);
            // Below code is just to createParameters for calling recievedResponse
            byte AA = (byte) ((responseBuffer.get(2) & 0b00000100));;
            int RCODE = (responseBuffer.get(3)) & 15;
            boolean isAuthoritative = AA == 4;
            this.listener.receivedResponse(TRANSACTION_ID,isAuthoritative,RCODE);
           ////////////////////////////////////////
            short QDCOUNT = responseBuffer.getShort(4);
            short ANCOUNT = responseBuffer.getShort(6);
            short NSCOUNT = responseBuffer.getShort(8);
            short ARCOUNT = responseBuffer.getShort(10);
            int nextIdx = 12;
            nextIdx = convertFQDN(responseBuffer, nextIdx);
            short QTYPE = responseBuffer.getShort(nextIdx);
            nextIdx += 2;
            short QCLASS = responseBuffer.getShort(nextIdx);
            nextIdx += 2;

            // Now calling listener's BeforeAnswerSection method.
            this.listener.beforeProcessingAnswerSection(ANCOUNT);

        for(int i = 0 ; i < ANCOUNT ; i++) {
            boolean isPointer = ((responseBuffer.get(nextIdx) & 0b11000000)) == 0b11000000;
            String Rname;
            if (isPointer) {
                Rname = convertBytesToName(responseBuffer, nextIdx);
                nextIdx += 2;
            } else {
                Rname = convertBytesToName(responseBuffer, nextIdx);
                nextIdx += Rname.length() + +(1 + 1);// 1 for null character 1 for pointer at size.
            }

            short Rtype = responseBuffer.getShort(nextIdx);
            nextIdx += 2;
            short Rclass = responseBuffer.getShort(nextIdx);
            nextIdx += 2;
            int TTL = responseBuffer.getInt(nextIdx);
            nextIdx += 4;
            short RdLength = responseBuffer.getShort(nextIdx);
            nextIdx += 2;
            String Rdata;
            if(Rtype == 5 || Rtype == 2) {
                Rdata = convertBytesToName(responseBuffer, nextIdx);
            }else if(Rtype == 15) {
                Rdata = convertBytesToName(responseBuffer, nextIdx + 2);
            }else if(Rtype ==  6 || Rtype == 0) {
             Rdata = createSOAparseStructure(responseBuffer,RdLength,nextIdx - 1);
            }else
             {
                Rdata = decodeIPV46(responseBuffer,RdLength,Rtype,nextIdx);
            }

            nextIdx += RdLength;
            ResourceRecord RR = createRR(Rname,Rtype,Rclass,TTL,Rdata);
            this.listener.receivedResourceRecord(RR,Rtype,Rclass);
            if(Rtype != 6 || Rtype != 0)
            this.cache.addResult(RR);
        }

            // Now calling listener's BeforeNameServer method.
            this.listener.beforeProcessingNameserversSection(NSCOUNT);

            for(int i = 0 ; i < NSCOUNT ; i++) {
                boolean isPointer = ((responseBuffer.get(nextIdx) & 0b11000000)) == 0b11000000;
                String Rname;
                if (isPointer) {
                    Rname = convertBytesToName(responseBuffer, nextIdx);
                    nextIdx += 2;
                } else {
                    Rname = convertBytesToName(responseBuffer, nextIdx);
                    nextIdx += Rname.length() + +(1 + 1);// 1 for null character 1 for pointer at size.
                }

                short Rtype = responseBuffer.getShort(nextIdx);
                nextIdx += 2;
                short Rclass = responseBuffer.getShort(nextIdx);
                nextIdx += 2;
                int TTL = responseBuffer.getInt(nextIdx);
                nextIdx += 4;
                short RdLength = responseBuffer.getShort(nextIdx);
                nextIdx += 2;
                String Rdata;
                if(Rtype == 2 || Rtype == 5)
                Rdata = convertBytesToName(responseBuffer, nextIdx);
                else if(Rtype == 15) {
                    Rdata = convertBytesToName(responseBuffer, nextIdx + 2);
                }else if(Rtype ==  6 || Rtype == 0) {
                    Rdata = createSOAparseStructure(responseBuffer,RdLength,nextIdx - 1);
                } else
                    Rdata = decodeIPV46(responseBuffer,RdLength,Rtype,nextIdx);
                nextIdx += RdLength;
                ResourceRecord RR = createRR(Rname,Rtype,Rclass,TTL,Rdata);
                this.listener.receivedResourceRecord(RR,Rtype,Rclass);
                if(Rtype != 6 || Rtype != 0)
                this.cache.addResult(RR);
                if(Rtype == 2)
                NS_RESULT.add(RR);
            }

            this.listener.beforeProcessingAdditionalRecordsSection(ARCOUNT);

        for(int i = 0 ; i < ARCOUNT ; i++) {
            boolean isPointer = ((responseBuffer.get(nextIdx) & 0b11000000)) == 0b11000000;
            String Rname;
            if (isPointer) {
                Rname = convertBytesToName(responseBuffer, nextIdx);
                nextIdx += 2;
            } else {
                Rname = convertBytesToName(responseBuffer, nextIdx);
                nextIdx += Rname.length() + +(1 + 1);// 1 for null character 1 for pointer at size.
            }

            short Rtype = responseBuffer.getShort(nextIdx);
            nextIdx += 2;
            short Rclass = responseBuffer.getShort(nextIdx);
            nextIdx += 2;
            int TTL = responseBuffer.getInt(nextIdx);
            nextIdx += 4;
            short RdLength = responseBuffer.getShort(nextIdx);
            nextIdx += 2;
            String Rdata;
            if(Rtype == 5 || Rtype == 2) {
                Rdata = convertBytesToName(responseBuffer, nextIdx);
            }else if(Rtype == 15) {
                Rdata = convertBytesToName(responseBuffer, nextIdx + 2);
            }else if(Rtype ==  6 || Rtype == 0) {
               Rdata = createSOAparseStructure(responseBuffer,RdLength,nextIdx - 1);
            }else {
                Rdata = decodeIPV46(responseBuffer,RdLength,Rtype,nextIdx);
            }
            nextIdx += RdLength;
            ResourceRecord RR = createRR(Rname,Rtype,Rclass,TTL,Rdata);
            this.listener.receivedResourceRecord(RR,Rtype,Rclass);
            if(Rtype != 6 || Rtype != 0)
            this.cache.addResult(RR);
        }

        return NS_RESULT;
    }

    /**
     * Access the ByteBuffer Object to convert SOA R-type to a specific Structure.
     * The SOA structure is parsed from bytes to hex representation in String.
     * @param responseBuffer - The bytebuffer which contains Rdata
     * @param Rdlength - length of R-data
     * @param pointer - pointer at which R-data starts.
     * @return hex representation of SOA R-data in form of string
     */

    private String createSOAparseStructure(ByteBuffer responseBuffer, short Rdlength, int pointer) {
        StringBuilder sb = new StringBuilder();
        for(int i = 0 ; i < Rdlength; i++) {
            sb.append(String.format("%02x",responseBuffer.get(pointer + i + 1)));
        }
        return sb.toString();
    }

    /**
     * take the fields of a resource record create a resource record in order to store it in cache.
     * @param RNAME - Name field of resource record.
     * @param RTYPE - type field of resource record.
     * @param RCLASS - Class field of resource record.
     * @param TTL - time to live of resource record.
     * @param RDATA - Rdata of resource record.
     * @return ResourceRecord that is needed to be stored in cache.
     */
    private ResourceRecord createRR(String RNAME, short RTYPE, short RCLASS, int TTL, String RDATA ) {
        ResourceRecord RR = null;
        try {
            RecordType RT = RecordType.getByCode(RTYPE);
            RecordClass RC = RecordClass.getByCode(RCLASS);
            DNSQuestion RRP1 = new DNSQuestion(RNAME, RT, RC);
            InetAddress IA;
            if(RTYPE == 1 || RTYPE == 28) {
                IA = InetAddress.getByName(RDATA);
                RR = new ResourceRecord(RRP1, TTL, IA);
            }else
             RR = new ResourceRecord(RRP1, TTL, RDATA);
        }catch (Exception ignored) {

        }
        return RR;
    }


    /**
     * takes values from bytebuffer which are in bytes and convert them to equivalent char values that concatenate them using stringbuilder
     * also appending . character after each label ending. In case the given pointer points to another pointer the destination that is the
     * pointer that contains label is reached iteratively.
     * @param responseBuffer the bytebuffer which stores the domain name
     * @param pointer the pointer that points to the first label size of the domain name or a pointer to a label name.
     * @return String representation of domain name
     */
    private String convertBytesToName(ByteBuffer responseBuffer, int pointer) {
        boolean isPointer = ((responseBuffer.get(pointer) & 0b11000000) == 0b11000000);
        int Size = responseBuffer.get(pointer);
        while(isPointer) {
            byte byteOne = (byte) (responseBuffer.get(pointer) & 0b00111111);
            byte byteTwo =  (responseBuffer.get(pointer + 1));
            short combinedPointer = (short) Short.toUnsignedInt((short) ((short) (byteOne << 8) | (byteTwo & 0xFF)));
            Size = responseBuffer.get(combinedPointer);
            pointer = combinedPointer;
            isPointer = ((responseBuffer.get(pointer) & 0b11000000) == 0b11000000);
        }
        StringBuilder sb = new StringBuilder();

        while(Size != 0) {
            byte[] label = new byte[Size];
            for(int i = 0 ; i < label.length ; i++) {
                label[i] = responseBuffer.get(pointer + i + 1);
            }
            sb.append(new String(label)).append(".");
            pointer = pointer + Size + 1;
            isPointer =  ((responseBuffer.get(pointer) & 0b11000000) == 0b11000000);
            while(isPointer) {
                byte byteOne = (byte) (responseBuffer.get(pointer) & 0b00111111);
                byte byteTwo =  (responseBuffer.get(pointer + 1));
                pointer = (short) Short.toUnsignedInt((short) ((short) (byteOne << 8) | (byteTwo & 0xFF)));
                isPointer = ((responseBuffer.get(pointer) & 0b11000000) == 0b11000000);
            }
            Size = responseBuffer.get(pointer);
        }
        return sb.substring(0,sb.length() - 1);
    }

    /**
     * Converts byte representation of IP address to its actual form with . representation that is for IPv4 its abc.def.gfy.ged
     * for IPv6 the bytes are converted to hex representation and the format is baba:adga:adf:a:b:c:d:defd
     * @param responseBuffer - The bytebuffer from which the data is to be extracted.
     * @param length - the length of the R-data of type A and AAAA.
     * @param type - the R-type of resourcerecord which can be A (IPv4) or AAAA (IPv6)
     * @param pointer - the pointer that points the start of the address.
     * @return string representaiton of IP address either of type A or AAAA.
     */

    private String decodeIPV46(ByteBuffer responseBuffer,int length, int type, int pointer ) {
        if(type == 1) {
            StringBuilder sb = new StringBuilder();
            for(int i = -1 ; i < length - 1; i++) {
                sb.append(Byte.toUnsignedInt(responseBuffer.get(pointer + i + 1)));
                sb.append(".");

            }
            return sb.substring(0,sb.length() - 1);
        }else {
            StringBuilder sb = new StringBuilder();
            for(int i = 0 ; i < length ; i+=2) {
                sb.append(Integer.toHexString(responseBuffer.getShort(pointer + i) & 0xffff));
                sb.append(":");
            }
            return sb.substring(0,sb.length() - 1);
        }
    }

    /**
     * Convert the question that is in the byte buffer to appropriate Domain name and returns the
     * pointer to the next attribute. FQDN - Fully Qualified Domain Name.
     * @param responseBuffer - the byteBuffer from which the data is to be extracted.
     * @param startIdx - the ponter which points to the first size of label
     * @return pointer to the next byte or short value which can be QTYPE followed by QCLASS
     */

    private int convertFQDN(ByteBuffer responseBuffer, Integer startIdx) {
        StringBuilder sb = new StringBuilder();
        int loopSize = responseBuffer.get(startIdx);
        while(loopSize != 0) {
            byte[] label = new byte[loopSize];
            for(int i = 0 ; i < loopSize ; i++) {
               label[i] = responseBuffer.get(startIdx + i + 1);
            }
            startIdx = startIdx + loopSize + 1;
            sb.append(new String(label)).append(".");
            loopSize = responseBuffer.get(startIdx);
        }
        String FQDN = (sb).substring(0,sb.length() - 1);
        return startIdx + 1;
    }

    /**
     * Helper function that converts a hex string representation of a byte array. May be used to represent the result of
     * records that are returned by the nameserver but not supported by the application (e.g., SOA records).
     *
     * @param data a byte array containing the record data.
     * @return A string containing the hex value of every byte in the data.
     */
    private static String byteArrayToHexString(byte[] data) {
        return IntStream.range(0, data.length).mapToObj(i -> String.format("%02x", data[i])).reduce("", String::concat);
    }

    public static class CnameIndirectionLimitException extends Exception {
    }
}
