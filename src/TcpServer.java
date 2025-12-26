import chat.*;
import com.google.gson.Gson;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.crypto.SecretKey;

public class TcpServer {
    public static final List<ClientHandler> clients = new ArrayList<>();
    public static final Gson gson = new Gson();

    public static void main(String[] args){
        System.out.println("🟢 SERVER PORNIT - HYBRID MODE (Tunel + E2E Pass-Through)");
        new Thread(TcpServer::tcpServer).start();
    }

    public static void tcpServer(){
        try(ServerSocket serverSocket = new ServerSocket(15555)){
            while (true){
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client conectat: " + clientSocket.getInetAddress());

                ClientHandler handler = new ClientHandler(clientSocket);
                new Thread(handler).start();
            }
        } catch (IOException e) {
            System.out.println("EROARE PORT 15555: " + e.getMessage());
        }
    }

    static class ClientHandler implements Runnable{
        private Socket socket;
        private ObjectOutputStream out;
        private ObjectInputStream in;

        private User currentUser = null;
        private int currentChatId = -1;
        private boolean isRunning = true;

        private SecretKey sessionKey = null; // Cheia Tunel (Server-Client)
        private PrivateKey tempKyberPrivate = null;

        public ClientHandler(Socket socket) {
            this.socket = socket;
            try{
                this.out = new ObjectOutputStream(socket.getOutputStream());
                this.in = new ObjectInputStream(socket.getInputStream());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        // AICI E LOGICA TA: Aceste pachete NU sunt criptate de Tunel pentru ca sunt deja criptate E2E
        // sau sunt prea mari/complexe sa le mai impachetam o data.
        private boolean isExemptFromTunnel(PacketType type) {
            return type == PacketType.SEND_MESSAGE ||
                    type == PacketType.RECEIVE_MESSAGE ||
                    type == PacketType.GET_MESSAGES_RESPONSE ||
                    type == PacketType.EDIT_MESSAGE_BROADCAST ||
                    type == PacketType.DELETE_MESSAGE_BROADCAST;
        }

        @Override
        public void run() {
            try {
                // 1. Handshake Initial (Kyber)
                if (!performHandshake()) {
                    System.out.println("❌ Handshake Esuat.");
                    disconnect();
                    return;
                }

                while (isRunning) {
                    String jsonRequest = (String) in.readObject();
                    NetworkPacket packet = NetworkPacket.fromJson(jsonRequest);

                    // --- LOGICA HIBRIDA ---

                    // CAZ 1: Pachet CRIPTAT prin TUNEL (Login, Create Chat, etc.)
                    if (packet.getType() == PacketType.SECURE_ENVELOPE) {
                        try {
                            String encryptedPayload = packet.getPayload().getAsString();
                            byte[] packedBytes = Base64.getDecoder().decode(encryptedPayload);
                            String originalJson = CryptoHelper.unpackAndDecrypt(sessionKey, packedBytes);

                            System.out.println("📥 [SERVER RECV] Pachet PRIMIT Criptat (AES): " + encryptedPayload);
                            packet = NetworkPacket.fromJson(originalJson);

                            // System.out.println("🔓 [TUNEL] Decriptat: " + packet.getType());
                        } catch (Exception e) {
                            System.out.println("🚨 Eroare decriptare Tunel!");
                            continue;
                        }
                    }
                    // CAZ 2: Pachet NECRIPTAT (EXEMPT) - Mesajele E2E
                    // Serverul le accepta asa cum sunt (JSON simplu), pentru ca payload-ul din ele e deja criptat de client
                    else if (isExemptFromTunnel(packet.getType())) {
                        System.out.println("📨 [PASS-THROUGH] Pachet E2E acceptat direct: " + packet.getType());
                    }
                    // CAZ 3: Pachet NECRIPTAT nepermis (Atac sau eroare)
                    else {
                        System.out.println("⚠️ Pachet necriptat nepermis: " + packet.getType());
                        continue;
                    }

                    // --- PROCESARE ---
                    switch (packet.getType()) {
                        case LOGIN_REQUEST: handleLogin(packet); break;
                        case REGISTER_REQUEST: handleRegister(packet); break;
                        case GET_CHATS_REQUEST: handleGetChats(); break;
                        case GET_USERS_REQUEST: handleGetUsersForAdd(); break;
                        case CREATE_CHAT_REQUEST: handleCreateChat(packet); break;
                        case DELETE_CHAT_REQUEST: handleDeleteChat(packet); break;
                        case RENAME_CHAT_REQUEST: handleRenameChat(packet); break;
                        case ENTER_CHAT_REQUEST: handleEnterChat(packet); break;
                        case EXIT_CHAT_REQUEST:
                            this.currentChatId = -1;
                            sendPacket(PacketType.EXIT_CHAT_RESPONSE, "BYE");
                            break;

                        // --- AICI MESAJUL VINE DEJA CRIPTAT E2E DE LA CLIENT ---
                        case SEND_MESSAGE: handleSendMessage(packet); break;

                        case EDIT_MESSAGE_REQUEST: handleEditMessage(packet); break;
                        case DELETE_MESSAGE_REQUEST: handleDeleteMessage(packet); break;
                        case LOGOUT: disconnect(); break;

                        default: System.out.println("Packet unknown: " + packet.getType());
                    }
                }
            } catch (Exception e) {
                disconnect();
            }
        }

        private boolean performHandshake() {
            try {
                System.out.println("⏳ Start Handshake Kyber...");
                KeyPair kyberPair = CryptoHelper.generateKyberKeys();
                this.tempKyberPrivate = kyberPair.getPrivate();
                byte[] pubBytes = kyberPair.getPublic().getEncoded();
                String pubBase64 = Base64.getEncoder().encodeToString(pubBytes);

                NetworkPacket hello = new NetworkPacket(PacketType.KYBER_SERVER_HELLO, 0, pubBase64);
                synchronized (out) { out.writeObject(hello.toJson()); out.flush(); }

                String responseJson = (String) in.readObject();
                NetworkPacket response = NetworkPacket.fromJson(responseJson);

                if (response.getType() == PacketType.KYBER_CLIENT_FINISH) {
                    String wrappedKeyBase64 = response.getPayload().getAsString();
                    byte[] wrappedBytes = Base64.getDecoder().decode(wrappedKeyBase64);
                    this.sessionKey = CryptoHelper.decapsulate(this.tempKyberPrivate, wrappedBytes);
                    this.tempKyberPrivate = null;
                    System.out.println("✅ TUNEL ACTIVAT!");
                    return true;
                }
                return false;
            } catch (Exception e) { return false; }
        }

        // --- HANDLERS ---

        private void handleLogin(NetworkPacket packet) throws IOException {
            ChatDtos.AuthDto dto = gson.fromJson(packet.getPayload(), ChatDtos.AuthDto.class);
            User user = Database.selectUserByUsername(dto.username);
            if (user != null && PasswordUtils.verifyPassword(dto.password, user.getSalt(), user.getPasswordHash())) {
                synchronized (clients) {
                    for (ClientHandler c : clients) {
                        if (c.currentUser != null && c.currentUser.getId() == user.getId()) {
                            sendPacket(PacketType.LOGIN_RESPONSE, "ALREADY"); return;
                        }
                    }
                    clients.add(this);
                }
                this.currentUser = user;
                Database.insertUserLog(user.getId(), "LOGIN", System.currentTimeMillis(), socket.getInetAddress().getHostAddress());
                sendPacket(PacketType.LOGIN_RESPONSE, user);
            } else {
                sendPacket(PacketType.LOGIN_RESPONSE, "FAIL");
            }
        }

        private void handleRegister(NetworkPacket packet) throws IOException {
            ChatDtos.AuthDto dto = gson.fromJson(packet.getPayload(), ChatDtos.AuthDto.class);
            if (Database.selectUserByUsername(dto.username) != null) {
                sendPacket(PacketType.REGISTER_RESPONSE, "EXISTS"); return;
            }
            String salt = PasswordUtils.generateSalt(50);
            String hash = PasswordUtils.hashPassword(dto.password, salt);
            Database.insertUser(dto.username, hash, salt, System.currentTimeMillis());
            User newUser = Database.selectUserByUsername(dto.username);
            this.currentUser = newUser;
            synchronized (clients) { clients.add(this); }
            sendPacket(PacketType.REGISTER_RESPONSE, newUser);
        }

        private void handleSendMessage(NetworkPacket packet) throws IOException {
            // Serverul primeste un JSON SEND_MESSAGE.
            // Payload-ul din interior (byte[]) este CRIPTAT CU CHEIA LOR (E2E).
            // Serverul NU POATE sa il citeasca. Doar il salveaza blob.

            Message receivedMsg = gson.fromJson(packet.getPayload(), Message.class);

            if (currentChatId == -1) return;

            long timestamp = System.currentTimeMillis();

            // Salvam BLOB-ul criptat in baza de date
            int msgId = Database.insertMessageReturningId(
                    receivedMsg.getContent(), // Asta e deja criptat AES Client-Client
                    timestamp,
                    currentUser.getId(),
                    currentChatId
            );

            // Construim obiectul complet
            Message fullMsg = new Message(msgId, receivedMsg.getContent(), timestamp, currentUser.getId(), currentChatId);

            // Trimitem la partener (FARA TUNEL, ca e in lista de EXEMPT)
            broadcastToPartner(currentChatId, PacketType.RECEIVE_MESSAGE, fullMsg);

            // Trimitem inapoi mie (confirmare)
            sendPacket(PacketType.RECEIVE_MESSAGE, fullMsg);
        }

        // --- CORE: TRIMITERE ---

        private void sendPacket(PacketType type, Object payload) throws IOException {
            int myId = (currentUser != null) ? currentUser.getId() : 0;
            NetworkPacket p = new NetworkPacket(type, myId, payload);
            sendDirectPacket(p);
        }

        private void sendDirectPacket(NetworkPacket p) throws IOException {
            // VERIFICARE CRITICA:
            // Daca pachetul e EXEMPT (Mesaj E2E) -> IL TRIMITEM "GOL" (fara Secure Envelope)
            // Daca pachetul e NORMAL (Login, etc) -> IL CRIPTAM CU TUNEL

            if (isExemptFromTunnel(p.getType())) {
                // PASS-THROUGH (Mesajul e deja securizat de client)
                synchronized (out) {
                    out.writeObject(p.toJson());
                    out.flush();
                }
            } else if (sessionKey != null) {
                // TUNEL (Securizam metadatele)
                try {
                    String clearJson = p.toJson();
                    byte[] encryptedBytes = CryptoHelper.encryptAndPack(sessionKey, clearJson);
                    String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedBytes);

                    System.out.println("📤 [SERVER SEND] Trimit Criptat (" + p.getType() + "): " + encryptedBase64);
                    NetworkPacket envelope = new NetworkPacket(PacketType.SECURE_ENVELOPE, p.getSenderId(), encryptedBase64);

                    synchronized (out) {
                        out.writeObject(envelope.toJson());
                        out.flush();
                    }
                } catch (Exception e) { e.printStackTrace(); }
            } else {
                // Handshake (cand nu avem cheie inca)
                synchronized (out) {
                    out.writeObject(p.toJson());
                    out.flush();
                }
            }
        }

        // --- RESTUL ---
        private void broadcastToPartner(int chatId, PacketType type, Object payload) {
            System.out.println("\n--- 📢 START BROADCAST (ChatID: " + chatId + ") ---");
            System.out.println("Sunt UserID: " + currentUser.getId() + " (" + currentUser.getUsername() + ")");

            // 1. Luam membrii din DB
            List<GroupMember> members = Database.selectGroupMembersByChatId(chatId);

            if (members == null || members.isEmpty()) {
                System.out.println("❌ EROARE CRITICA: DB-ul zice ca nu sunt membri in grupul asta!");
                System.out.println("--- 🛑 END BROADCAST ---\n");
                return;
            }

            System.out.println("📋 Membri in grup (din DB): " + members.size());

            // Afisam cine e conectat la server in acest moment (RAM)
            synchronized (clients) {
                System.out.print("🔌 Useri Conectati la Server (Socketi activi): [ ");
                for (ClientHandler c : clients) {
                    if (c.currentUser != null) {
                        System.out.print(c.currentUser.getId() + " ");
                    } else {
                        System.out.print("?(nelogat) ");
                    }
                }
                System.out.println("]");
            }

            // 2. Iteram prin membri
            for (GroupMember m : members) {
                int targetId = m.getUserId();
                System.out.println("   👉 Verific membrul ID: " + targetId);

                // Il sarim pe cel care a trimis (eu)
                if (targetId == currentUser.getId()) {
                    System.out.println("      Skipping: Sunt eu.");
                    continue;
                }

                boolean sent = false;

                // Cautam user-ul in lista de socket-uri
                synchronized (clients) {
                    for (ClientHandler client : clients) {
                        if (client.currentUser != null && client.currentUser.getId() == targetId) {
                            try {
                                System.out.println("      ✅ GASIT ONLINE! Trimit pachet...");

                                NetworkPacket p = new NetworkPacket(type, currentUser.getId(), payload);
                                client.sendDirectPacket(p);

                                sent = true;
                                System.out.println("      📨 Pachet livrat pe socket.");
                            } catch (IOException e) {
                                System.out.println("      ❌ Eroare socket: " + e.getMessage());
                            }
                            break;
                        }
                    }
                }

                if (!sent) {
                    System.out.println("      💤 Userul ID " + targetId + " este OFFLINE (nu e in lista de socketi).");
                }
            }
            System.out.println("--- 🏁 END BROADCAST ---\n");
        }

        // Metode standard (create, enter, etc) ramase la fel...
        private void handleGetChats() throws IOException {
            if (currentUser == null) return;
            sendPacket(PacketType.GET_CHATS_RESPONSE, Database.selectGroupChatsByUserId(currentUser.getId()));
        }
        private void handleGetUsersForAdd() throws IOException {
            List<String> rawUsers = Database.selectUsersAddConversation();
            List<String> filtered = new ArrayList<>();
            for (String u : rawUsers) {
                int uid = Integer.parseInt(u.split(",")[0]);
                if (uid != currentUser.getId() && uid != -1) filtered.add(u);
            }
            sendPacket(PacketType.GET_USERS_RESPONSE, filtered);
        }
        private void handleCreateChat(NetworkPacket packet) throws IOException {
            ChatDtos.CreateGroupDto dto = gson.fromJson(packet.getPayload(), ChatDtos.CreateGroupDto.class);
            Database.insertGroupChat(dto.groupName);
            GroupChat newChat = Database.selectGroupChatByName(dto.groupName);
            if (newChat != null) {
                Database.insertGroupMember(newChat.getId(), currentUser.getId());
                Database.insertGroupMember(newChat.getId(), dto.targetUserId);
                sendPacket(PacketType.CREATE_CHAT_RESPONSE, newChat);
            }
        }
        private void handleEnterChat(NetworkPacket packet) throws IOException {
            int chatId = gson.fromJson(packet.getPayload(), Integer.class);
            this.currentChatId = chatId;
            sendPacket(PacketType.ENTER_CHAT_RESPONSE, "OK");
            List<Message> history = Database.selectMessagesByGroup(chatId);
            // Istoricul vine prin EXEMPT (deja criptat in DB)
            sendPacket(PacketType.GET_MESSAGES_RESPONSE, history);
        }
        private void handleRenameChat(NetworkPacket packet) throws IOException {
            ChatDtos.RenameGroupDto dto = gson.fromJson(packet.getPayload(), ChatDtos.RenameGroupDto.class);
            Database.updateGroupChatName(dto.chatId, dto.newName);
            sendPacket(PacketType.RENAME_CHAT_RESPONSE, "OK");
        }
        private void handleDeleteChat(NetworkPacket packet) throws IOException {
            int chatId = gson.fromJson(packet.getPayload(), Integer.class);
            Database.deleteGroupChatTransactional(chatId);
            sendPacket(PacketType.DELETE_CHAT_RESPONSE, "OK");
        }
        private void handleEditMessage(NetworkPacket packet) throws IOException {
            ChatDtos.EditMessageDto dto = gson.fromJson(packet.getPayload(), ChatDtos.EditMessageDto.class);
            if (Database.updateMessageById(dto.messageId, dto.newContent)) {
                if (currentChatId != -1) {
                    broadcastToPartner(currentChatId, PacketType.EDIT_MESSAGE_BROADCAST, dto);
                    sendPacket(PacketType.EDIT_MESSAGE_BROADCAST, dto);
                }
            }
        }
        private void handleDeleteMessage(NetworkPacket packet) throws IOException {
            int msgId = gson.fromJson(packet.getPayload(), Integer.class);
            if (Database.deleteMessageById(msgId)) {
                if (currentChatId != -1) {
                    broadcastToPartner(currentChatId, PacketType.DELETE_MESSAGE_BROADCAST, msgId);
                    sendPacket(PacketType.DELETE_MESSAGE_BROADCAST, msgId);
                }
            }
        }

        private void disconnect() {
            isRunning = false;
            synchronized (clients) { clients.remove(this); }
            try { socket.close(); } catch (IOException e) {}
            System.out.println("Client deconectat.");
        }
    }
}