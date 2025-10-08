package com.hdlogin;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.player.*;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitRunnable;

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class HDLoginPlugin extends JavaPlugin implements Listener {
    
    private FileConfiguration config;
    private FileConfiguration dataConfig;
    private File dataFile;
    
    private Set<String> loggedInPlayers = ConcurrentHashMap.newKeySet();
    private Map<String, Integer> failedAttempts = new ConcurrentHashMap<>();
    private Map<String, Long> loginBans = new ConcurrentHashMap<>();
    private Map<String, BukkitRunnable> loginTimeouts = new ConcurrentHashMap<>();
    private Map<String, String> playerIPs = new ConcurrentHashMap<>(); // 玩家名 -> IP地址
    private Map<String, Set<String>> ipPlayers = new ConcurrentHashMap<>(); // IP地址 -> 玩家名集合
    
    private int maxPasswordLength;
    private int minPasswordLength;
    private int loginTimeout;
    private int maxFailedAttempts;
    private int banDuration;
    private int maxAccountsPerIP;
    
    @Override
    public void onEnable() {
        // 显示ASCII标题
        printAsciiTitle();
        
        getLogger().info("正在初始化HDLogin插件...");
        
        // 创建配置文件
        getLogger().info("加载配置文件中...");
        saveDefaultConfig();
        loadConfig();
        getLogger().info("✓ 配置文件加载完成");
        
        // 创建数据文件
        getLogger().info("初始化数据文件中...");
        setupDataFile();
        
        // 加载玩家IP数据
        getLogger().info("加载玩家IP数据中...");
        loadPlayerIPs();
        getLogger().info("✓ 数据文件初始化完成");
        
        // 注册事件监听器
        getLogger().info("注册事件监听器中...");
        getServer().getPluginManager().registerEvents(this, this);
        getLogger().info("✓ 事件监听器注册完成");
        
        // 注册命令
        getLogger().info("注册命令处理器中...");
        getCommand("slogin").setExecutor(this);
        getCommand("login").setExecutor(this);
        getCommand("register").setExecutor(this);
        getCommand("changepassword").setExecutor(this);
        getCommand("unregister").setExecutor(this);
        getCommand("unloginban").setExecutor(this);
        getCommand("forcelogin").setExecutor(this);
        getLogger().info("✓ 命令处理器注册完成");
        
        // 显示配置信息
        displayConfigInfo();
        
        getLogger().info("✓ HDLogin插件已成功启用!");
        getLogger().info("===============================================");
    }
    
    @Override
    public void onDisable() {
        getLogger().info("正在关闭HDLogin插件...");
        
        // 取消所有定时任务
        getLogger().info("清理登录超时任务中...");
        for (BukkitRunnable task : loginTimeouts.values()) {
            if (task != null) {
                task.cancel();
            }
        }
        loginTimeouts.clear();
        getLogger().info("✓ 登录超时任务清理完成");
        
        getLogger().info("===============================================");
        getLogger().info("✓ HDLogin插件已成功禁用!");
    }
    
    private void printAsciiTitle() {
        getLogger().info("===============================================");
        getLogger().info("  #     #  ######   #                                  ");
        getLogger().info("  #     #  #     #  #         ####    ####   #  #    # ");
        getLogger().info("  #     #  #     #  #        #    #  #    #  #  ##   # ");
        getLogger().info("  #######  #     #  #        #    #  #       #  # #  # ");
        getLogger().info("  #     #  #     #  #        #    #  #  ###  #  #  # # ");
        getLogger().info("  #     #  #     #  #        #    #  #    #  #  #   ## ");
        getLogger().info("  #     #  ######   #######   ####    ####   #  #    #");
        getLogger().info("===============================================");
        getLogger().info("版本: " + getDescription().getVersion());
        getLogger().info("作者: " + getDescription().getAuthors());
        getLogger().info("===============================================");
    }
    
    private void displayConfigInfo() {
        getLogger().info("当前配置信息:");
        getLogger().info("  • 密码长度限制: " + minPasswordLength + " - " + maxPasswordLength + " 字符");
        getLogger().info("  • 登录超时时间: " + loginTimeout + " 秒");
        getLogger().info("  • 最大失败尝试: " + maxFailedAttempts + " 次");
        getLogger().info("  • 封禁持续时间: " + banDuration + " 分钟");
        getLogger().info("  • 每IP最大账号数: " + maxAccountsPerIP + " 个");
        getLogger().info("  • 已注册命令: slogin, login, register, changepassword, unregister, unloginban, forcelogin");
        
        // 显示已注册玩家数量
        if (dataConfig.getConfigurationSection("players") != null) {
            int playerCount = dataConfig.getConfigurationSection("players").getKeys(false).size();
            getLogger().info("  • 已注册玩家数量: " + playerCount + " 个");
        } else {
            getLogger().info("  • 已注册玩家数量: 0 个");
        }
        
        getLogger().info("===============================================");
    }
    
    private void loadConfig() {
        config = getConfig();
        maxPasswordLength = config.getInt("settings.max-password-length", 16);
        minPasswordLength = config.getInt("settings.min-password-length", 4);
        loginTimeout = config.getInt("settings.login-timeout", 30);
        maxFailedAttempts = config.getInt("settings.max-failed-attempts", 5);
        banDuration = config.getInt("settings.ban-duration", 30);
        maxAccountsPerIP = config.getInt("settings.max-accounts-per-ip", 3);
    }
    
    private void setupDataFile() {
        dataFile = new File(getDataFolder(), "data.yml");
        if (!dataFile.exists()) {
            try {
                dataFile.getParentFile().mkdirs();
                dataFile.createNewFile();
            } catch (IOException e) {
                getLogger().severe("无法创建数据文件: " + e.getMessage());
            }
        }
        dataConfig = YamlConfiguration.loadConfiguration(dataFile);
    }
    
    private void saveData() {
        try {
            dataConfig.save(dataFile);
        } catch (IOException e) {
            getLogger().severe("无法保存数据文件: " + e.getMessage());
        }
    }
    
    // IP地址管理方法
    private String getPlayerIP(Player player) {
        return player.getAddress().getAddress().getHostAddress();
    }
    
    private void addPlayerIP(String playerName, String ipAddress) {
        playerName = playerName.toLowerCase();
        
        // 如果玩家已有IP记录，先移除旧的
        if (playerIPs.containsKey(playerName)) {
            String oldIP = playerIPs.get(playerName);
            if (ipPlayers.containsKey(oldIP)) {
                ipPlayers.get(oldIP).remove(playerName);
                if (ipPlayers.get(oldIP).isEmpty()) {
                    ipPlayers.remove(oldIP);
                }
            }
        }
        
        // 添加新的IP记录
        playerIPs.put(playerName, ipAddress);
        
        if (!ipPlayers.containsKey(ipAddress)) {
            ipPlayers.put(ipAddress, ConcurrentHashMap.newKeySet());
        }
        ipPlayers.get(ipAddress).add(playerName);
        
        // 保存到数据文件
        dataConfig.set("player-ips." + playerName, ipAddress);
        saveData();
    }
    
    private void removePlayerIP(String playerName) {
        playerName = playerName.toLowerCase();
        
        if (playerIPs.containsKey(playerName)) {
            String ipAddress = playerIPs.get(playerName);
            playerIPs.remove(playerName);
            
            if (ipPlayers.containsKey(ipAddress)) {
                ipPlayers.get(ipAddress).remove(playerName);
                if (ipPlayers.get(ipAddress).isEmpty()) {
                    ipPlayers.remove(ipAddress);
                }
            }
            
            // 从数据文件移除
            dataConfig.set("player-ips." + playerName, null);
            saveData();
        }
    }
    
    private int getAccountsCountForIP(String ipAddress) {
        if (ipPlayers.containsKey(ipAddress)) {
            return ipPlayers.get(ipAddress).size();
        }
        return 0;
    }
    
    private Set<String> getPlayersForIP(String ipAddress) {
        if (ipPlayers.containsKey(ipAddress)) {
            return new HashSet<>(ipPlayers.get(ipAddress));
        }
        return new HashSet<>();
    }
    
    private void loadPlayerIPs() {
        if (dataConfig.getConfigurationSection("player-ips") != null) {
            for (String playerName : dataConfig.getConfigurationSection("player-ips").getKeys(false)) {
                String ipAddress = dataConfig.getString("player-ips." + playerName);
                if (ipAddress != null) {
                    playerIPs.put(playerName.toLowerCase(), ipAddress);
                    
                    if (!ipPlayers.containsKey(ipAddress)) {
                        ipPlayers.put(ipAddress, ConcurrentHashMap.newKeySet());
                    }
                    ipPlayers.get(ipAddress).add(playerName.toLowerCase());
                }
            }
        }
    }
    
    // 密码加密方法
    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            md.update(salt);
            byte[] hashedPassword = md.digest(password.getBytes());
            
            // 将盐和哈希值一起存储
            return Base64.getEncoder().encodeToString(salt) + ":" + 
                   Base64.getEncoder().encodeToString(hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            getLogger().severe("密码加密算法不可用: " + e.getMessage());
            return null;
        }
    }
    
    private boolean verifyPassword(String password, String storedHash) {
        try {
            String[] parts = storedHash.split(":");
            if (parts.length != 2) return false;
            
            byte[] salt = Base64.getDecoder().decode(parts[0]);
            byte[] expectedHash = Base64.getDecoder().decode(parts[1]);
            
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] actualHash = md.digest(password.getBytes());
            
            return MessageDigest.isEqual(expectedHash, actualHash);
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean isPlayerLoggedIn(Player player) {
        return loggedInPlayers.contains(player.getName().toLowerCase());
    }
    
    private boolean isPlayerRegistered(String playerName) {
        return dataConfig.contains("players." + playerName.toLowerCase());
    }
    
    private void startLoginTimeout(Player player) {
        String playerName = player.getName().toLowerCase();
        
        // 取消现有的超时任务
        if (loginTimeouts.containsKey(playerName)) {
            loginTimeouts.get(playerName).cancel();
        }
        
        BukkitRunnable task = new BukkitRunnable() {
            @Override
            public void run() {
                if (!isPlayerLoggedIn(player)) {
                    String message = config.getString("messages.login-timeout-kick", "&c登录超时，请重新加入服务器!");
                    player.kickPlayer(ChatColor.translateAlternateColorCodes('&', message));
                }
                loginTimeouts.remove(playerName);
            }
        };
        
        task.runTaskLater(this, loginTimeout * 20L); // 转换为ticks
        loginTimeouts.put(playerName, task);
    }
    
    private void cancelLoginTimeout(String playerName) {
        playerName = playerName.toLowerCase();
        if (loginTimeouts.containsKey(playerName)) {
            loginTimeouts.get(playerName).cancel();
            loginTimeouts.remove(playerName);
        }
    }
    
    private boolean isLoginBanned(String playerName) {
        playerName = playerName.toLowerCase();
        if (loginBans.containsKey(playerName)) {
            long banTime = loginBans.get(playerName);
            if (System.currentTimeMillis() - banTime < banDuration * 60 * 1000) {
                return true;
            } else {
                loginBans.remove(playerName);
                failedAttempts.remove(playerName);
            }
        }
        return false;
    }
    
    // 事件处理
    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        String playerName = player.getName().toLowerCase();
        String playerIP = getPlayerIP(player);
        
        // 检查是否被登录封禁
        if (isLoginBanned(playerName)) {
            long remainingTime = (banDuration * 60 * 1000) - (System.currentTimeMillis() - loginBans.get(playerName));
            long minutes = remainingTime / (60 * 1000);
            long seconds = (remainingTime % (60 * 1000)) / 1000;
            
            String message = config.getString("messages.temp-ban-kick", "&c密码错误次数过多，请等待{minutes}分{seconds}秒后再试!")
                    .replace("{minutes}", String.valueOf(minutes))
                    .replace("{seconds}", String.valueOf(seconds));
            
            player.kickPlayer(ChatColor.translateAlternateColorCodes('&', message));
            return;
        }
        
        // 检查IP限制（仅对新玩家）
        if (!isPlayerRegistered(playerName)) {
            int accountsCount = getAccountsCountForIP(playerIP);
            if (accountsCount >= maxAccountsPerIP) {
                String message = config.getString("messages.ip-limit-kick", "&c此IP地址已注册了{max}个账号，无法注册新账号!")
                        .replace("{max}", String.valueOf(maxAccountsPerIP));
                player.kickPlayer(ChatColor.translateAlternateColorCodes('&', message));
                return;
            }
        }
        
        // 重置失败尝试次数
        failedAttempts.remove(playerName);
        
        if (isPlayerRegistered(playerName)) {
            // 已注册玩家需要登录
            String message = config.getString("messages.please-login", "&a请使用 /login <密码> 登录!");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            
            // 显示同IP账号信息
            Set<String> sameIPPlayers = getPlayersForIP(playerIP);
            if (sameIPPlayers.size() > 1) {
                sameIPPlayers.remove(playerName); // 移除当前玩家
                if (!sameIPPlayers.isEmpty()) {
                    String sameIPMessage = config.getString("messages.same-ip-players", "&6同IP地址下还有以下账号: {players}")
                            .replace("{players}", String.join(", ", sameIPPlayers));
                    player.sendMessage(ChatColor.translateAlternateColorCodes('&', sameIPMessage));
                }
            }
        } else {
            // 新玩家需要注册
            String message = config.getString("messages.please-register", "&a请使用 /register <密码> 注册账号!");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
        }
        
        // 开始登录超时计时
        startLoginTimeout(player);
    }
    
    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent event) {
        Player player = event.getPlayer();
        String playerName = player.getName().toLowerCase();
        
        // 取消登录超时
        cancelLoginTimeout(playerName);
        
        // 移除登录状态
        loggedInPlayers.remove(playerName);
    }
    
    // 阻止未登录玩家的交互
    @EventHandler
    public void onPlayerMove(PlayerMoveEvent event) {
        Player player = event.getPlayer();
        if (!isPlayerLoggedIn(player) && event.getFrom().distanceSquared(event.getTo()) > 0) {
            event.setTo(event.getFrom());
        }
    }
    
    @EventHandler
    public void onPlayerInteract(PlayerInteractEvent event) {
        if (!isPlayerLoggedIn(event.getPlayer())) {
            event.setCancelled(true);
        }
    }
    
    @EventHandler
    public void onBlockBreak(BlockBreakEvent event) {
        if (!isPlayerLoggedIn(event.getPlayer())) {
            event.setCancelled(true);
        }
    }
    
    @EventHandler
    public void onBlockPlace(BlockPlaceEvent event) {
        if (!isPlayerLoggedIn(event.getPlayer())) {
            event.setCancelled(true);
        }
    }
    
    @EventHandler
    public void onEntityDamageByEntity(EntityDamageByEntityEvent event) {
        if (event.getDamager() instanceof Player) {
            Player player = (Player) event.getDamager();
            if (!isPlayerLoggedIn(player)) {
                event.setCancelled(true);
            }
        }
    }
    
    @EventHandler
    public void onPlayerCommandPreprocess(PlayerCommandPreprocessEvent event) {
        Player player = event.getPlayer();
        if (!isPlayerLoggedIn(player)) {
            String message = event.getMessage().toLowerCase();
            // 只允许登录相关命令
            if (!message.startsWith("/login") && !message.startsWith("/register")) {
                event.setCancelled(true);
                String cancelMessage = config.getString("messages.command-blocked", "&c请先登录后再使用命令!");
                player.sendMessage(ChatColor.translateAlternateColorCodes('&', cancelMessage));
            }
        }
    }
    
    @EventHandler
    public void onAsyncPlayerChat(AsyncPlayerChatEvent event) {
        Player player = event.getPlayer();
        if (!isPlayerLoggedIn(player)) {
            event.setCancelled(true);
            String cancelMessage = config.getString("messages.chat-blocked", "&c请先登录后再聊天!");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', cancelMessage));
        }
    }
    
    // 命令处理
    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        String commandName = command.getName().toLowerCase();
        
        // 检查是否为需要玩家执行的命令
        if (!(sender instanceof Player)) {
            // 如果是控制台，只允许执行非玩家专属命令
            switch (commandName) {
                case "login":
                case "register":
                case "changepassword":
                case "unregister":
                    sender.sendMessage(ChatColor.RED + "此命令只能由玩家执行!");
                    return true;
                default:
                    // 其他命令允许控制台执行
                    break;
            }
        }
        
        // 如果是玩家，正常处理所有命令
        if (sender instanceof Player) {
            Player player = (Player) sender;
            String playerName = player.getName().toLowerCase();
            
            switch (commandName) {
                case "slogin":
                    return handleSlogin(player, args);
                case "login":
                    return handleLogin(player, args);
                case "register":
                    return handleRegister(player, args);
                case "changepassword":
                    return handleChangePassword(player, args);
                case "unregister":
                    return handleUnregister(player, args);
                case "unloginban":
                    return handleUnloginban(player, args);
                case "forcelogin":
                    return handleForcelogin(player, args);
            }
        } else {
            // 控制台执行非玩家专属命令
            switch (commandName) {
                case "slogin":
                    return handleSloginConsole(sender, args);
                case "unloginban":
                    return handleUnloginbanConsole(sender, args);
                case "forcelogin":
                    return handleForceloginConsole(sender, args);
            }
        }
        
        return false;
    }
    
    private boolean handleSlogin(Player player, String[] args) {
        if (args.length == 0) {
            // 显示插件信息
            player.sendMessage(ChatColor.GREEN + "=== HDLogin 插件信息 ===");
            player.sendMessage(ChatColor.YELLOW + "版本: " + getDescription().getVersion());
            player.sendMessage(ChatColor.YELLOW + "作者: " + getDescription().getAuthors());
            player.sendMessage(ChatColor.YELLOW + "用法: /slogin reload - 重新加载配置");
            player.sendMessage(ChatColor.YELLOW + "用法: /slogin - 显示插件信息");
            return true;
        }
        
        if (args.length == 1 && args[0].equalsIgnoreCase("reload")) {
            // 检查权限
            if (!player.hasPermission("hdlogin.admin")) {
                String message = config.getString("messages.no-permission", "&c你没有权限执行此命令!");
                player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
                return true;
            }
            
            // 重新加载配置
            reloadConfig();
            loadConfig();
            
            String message = config.getString("messages.config-reloaded", "&a配置已成功重新加载!");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            
            getLogger().info("配置已通过命令重新加载 - 由 " + player.getName() + " 执行");
            return true;
        }
        
        // 无效参数
        player.sendMessage(ChatColor.RED + "用法: /slogin [reload]");
        return true;
    }
    
    private boolean handleLogin(Player player, String[] args) {
        String playerName = player.getName().toLowerCase();
        
        if (isPlayerLoggedIn(player)) {
            String message = config.getString("messages.already-logged-in", "&c你已经登录了!");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        if (!isPlayerRegistered(playerName)) {
            String message = config.getString("messages.not-registered", "&c你还没有注册，请使用 /register <密码> 注册!");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        if (args.length != 1) {
            String message = config.getString("messages.login-usage", "&c用法: /login <密码>");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        String password = args[0];
        String storedHash = dataConfig.getString("players." + playerName);
        
        if (verifyPassword(password, storedHash)) {
            // 登录成功
            loggedInPlayers.add(playerName);
            failedAttempts.remove(playerName);
            cancelLoginTimeout(playerName);
            
            // 记录玩家IP地址
            String playerIP = getPlayerIP(player);
            addPlayerIP(playerName, playerIP);
            
            String message = config.getString("messages.login-success", "&a登录成功!");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
        } else {
            // 登录失败
            int attempts = failedAttempts.getOrDefault(playerName, 0) + 1;
            failedAttempts.put(playerName, attempts);
            
            if (attempts >= maxFailedAttempts) {
                // 封禁玩家
                loginBans.put(playerName, System.currentTimeMillis());
                String message = config.getString("messages.too-many-attempts-kick", "&c密码错误次数过多，请等待{minutes}分钟后再试!")
                        .replace("{minutes}", String.valueOf(banDuration));
                player.kickPlayer(ChatColor.translateAlternateColorCodes('&', message));
            } else {
                String message = config.getString("messages.login-failed", "&c密码错误! 剩余尝试次数: {attempts}")
                        .replace("{attempts}", String.valueOf(maxFailedAttempts - attempts));
                player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            }
        }
        
        return true;
    }
    
    private boolean handleRegister(Player player, String[] args) {
        String playerName = player.getName().toLowerCase();
        
        if (isPlayerLoggedIn(player)) {
            String message = config.getString("messages.already-logged-in", "&c你已经登录了!");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        if (isPlayerRegistered(playerName)) {
            String message = config.getString("messages.already-registered", "&c你已经注册过了，请使用 /login <密码> 登录!");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        if (args.length != 1) {
            String message = config.getString("messages.register-usage", "&c用法: /register <密码>");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        String password = args[0];
        
        if (password.length() < minPasswordLength) {
            String message = config.getString("messages.password-too-short", "&c密码太短! 最少需要{min}个字符!")
                    .replace("{min}", String.valueOf(minPasswordLength));
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        if (password.length() > maxPasswordLength) {
            String message = config.getString("messages.password-too-long", "&c密码太长! 最多允许{max}个字符!")
                    .replace("{max}", String.valueOf(maxPasswordLength));
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        // 注册成功
        String hashedPassword = hashPassword(password);
        dataConfig.set("players." + playerName, hashedPassword);
        saveData();
        
        loggedInPlayers.add(playerName);
        cancelLoginTimeout(playerName);
        
        // 记录玩家IP地址
        String playerIP = getPlayerIP(player);
        addPlayerIP(playerName, playerIP);
        
        String message = config.getString("messages.register-success", "&a注册成功! 已自动登录。");
        player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
        
        return true;
    }
    
    private boolean handleChangePassword(Player player, String[] args) {
        String playerName = player.getName().toLowerCase();
        
        if (!isPlayerLoggedIn(player)) {
            String message = config.getString("messages.not-logged-in", "&c请先登录后再修改密码!");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        if (args.length != 2) {
            String message = config.getString("messages.changepassword-usage", "&c用法: /changepassword <旧密码> <新密码>");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        String oldPassword = args[0];
        String newPassword = args[1];
        
        // 验证旧密码是否正确
        String storedHash = dataConfig.getString("players." + playerName);
        if (!verifyPassword(oldPassword, storedHash)) {
            String message = config.getString("messages.old-password-wrong", "&c旧密码错误!");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        if (newPassword.length() < minPasswordLength) {
            String message = config.getString("messages.password-too-short", "&c密码太短! 最少需要{min}个字符!")
                    .replace("{min}", String.valueOf(minPasswordLength));
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        if (newPassword.length() > maxPasswordLength) {
            String message = config.getString("messages.password-too-long", "&c密码太长! 最多允许{max}个字符!")
                    .replace("{max}", String.valueOf(maxPasswordLength));
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        // 修改密码成功
        String hashedPassword = hashPassword(newPassword);
        dataConfig.set("players." + playerName, hashedPassword);
        saveData();
        
        String message = config.getString("messages.password-changed", "&a密码修改成功!");
        player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
        
        return true;
    }
    
    private boolean handleUnregister(Player player, String[] args) {
        String playerName = player.getName().toLowerCase();
        
        if (!isPlayerLoggedIn(player)) {
            String message = config.getString("messages.not-logged-in", "&c请先登录后再注销账号!");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        if (!isPlayerRegistered(playerName)) {
            String message = config.getString("messages.not-registered", "&c你还没有注册账号!");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        // 注销成功
        dataConfig.set("players." + playerName, null);
        saveData();
        
        // 移除玩家IP记录
        removePlayerIP(playerName);
        
        loggedInPlayers.remove(playerName);
        
        String message = config.getString("messages.unregister-success", "&a账号已成功注销!");
        player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
        
        // 踢出玩家
        String kickMessage = config.getString("messages.unregister-kick", "&a你的账号已被注销!");
        player.kickPlayer(ChatColor.translateAlternateColorCodes('&', kickMessage));
        
        return true;
    }
    
    private boolean handleUnloginban(Player player, String[] args) {
        if (!player.hasPermission("hdlogin.admin")) {
            String message = config.getString("messages.no-permission", "&c你没有权限执行此命令!");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        if (args.length != 1) {
            String message = config.getString("messages.unloginban-usage", "&c用法: /unloginban <玩家名>");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        String targetPlayer = args[0].toLowerCase();
        
        if (!loginBans.containsKey(targetPlayer)) {
            String message = config.getString("messages.player-not-banned", "&c玩家 {player} 没有被登录封禁!")
                    .replace("{player}", targetPlayer);
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        // 解除封禁
        loginBans.remove(targetPlayer);
        failedAttempts.remove(targetPlayer);
        
        String message = config.getString("messages.unban-success", "&a已解除 {player} 的登录封禁!")
                .replace("{player}", targetPlayer);
        player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
        
        return true;
    }
    
    private boolean handleForcelogin(Player player, String[] args) {
        if (!player.hasPermission("hdlogin.admin")) {
            String message = config.getString("messages.no-permission", "&c你没有权限执行此命令!");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        if (args.length != 1) {
            String message = config.getString("messages.forcelogin-usage", "&c用法: /forcelogin <玩家名>");
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        String targetPlayerName = args[0].toLowerCase();
        Player targetPlayer = getServer().getPlayer(targetPlayerName);
        
        if (targetPlayer == null) {
            String message = config.getString("messages.player-not-online", "&c玩家 {player} 不在线!")
                    .replace("{player}", targetPlayerName);
            player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
            return true;
        }
        
        // 强制登录玩家
        loggedInPlayers.add(targetPlayerName);
        failedAttempts.remove(targetPlayerName);
        cancelLoginTimeout(targetPlayerName);
        
        String message = config.getString("messages.forcelogin-success", "&a已强制登录 {player}!")
                .replace("{player}", targetPlayerName);
        player.sendMessage(ChatColor.translateAlternateColorCodes('&', message));
        
        String targetMessage = config.getString("messages.force-logged-in", "&a你已被管理员强制登录!");
        targetPlayer.sendMessage(ChatColor.translateAlternateColorCodes('&', targetMessage));
        
        return true;
    }
    
    // 控制台命令处理方法
    private boolean handleSloginConsole(CommandSender sender, String[] args) {
        if (args.length == 0) {
            // 显示插件信息
            sender.sendMessage("=== HDLogin 插件信息 ===");
            sender.sendMessage("版本: " + getDescription().getVersion());
            sender.sendMessage("作者: " + getDescription().getAuthors());
            sender.sendMessage("用法: slogin reload - 重新加载配置");
            sender.sendMessage("用法: slogin - 显示插件信息");
            return true;
        }
        
        if (args.length == 1 && args[0].equalsIgnoreCase("reload")) {
            // 重新加载配置
            reloadConfig();
            loadConfig();
            
            sender.sendMessage("配置已成功重新加载!");
            getLogger().info("配置已通过控制台命令重新加载");
            return true;
        }
        
        // 无效参数
        sender.sendMessage("用法: slogin [reload]");
        return true;
    }
    
    private boolean handleUnloginbanConsole(CommandSender sender, String[] args) {
        if (args.length != 1) {
            sender.sendMessage("用法: unloginban <玩家名>");
            return true;
        }
        
        String targetPlayer = args[0].toLowerCase();
        
        if (!loginBans.containsKey(targetPlayer)) {
            sender.sendMessage("玩家 " + targetPlayer + " 没有被登录封禁!");
            return true;
        }
        
        // 解除封禁
        loginBans.remove(targetPlayer);
        failedAttempts.remove(targetPlayer);
        
        sender.sendMessage("已解除 " + targetPlayer + " 的登录封禁!");
        getLogger().info("控制台已解除玩家 " + targetPlayer + " 的登录封禁");
        return true;
    }
    
    private boolean handleForceloginConsole(CommandSender sender, String[] args) {
        if (args.length != 1) {
            sender.sendMessage("用法: forcelogin <玩家名>");
            return true;
        }
        
        String targetPlayerName = args[0].toLowerCase();
        Player targetPlayer = getServer().getPlayer(targetPlayerName);
        
        if (targetPlayer == null) {
            sender.sendMessage("玩家 " + targetPlayerName + " 不在线!");
            return true;
        }
        
        // 强制登录玩家
        loggedInPlayers.add(targetPlayerName);
        failedAttempts.remove(targetPlayerName);
        cancelLoginTimeout(targetPlayerName);
        
        sender.sendMessage("已强制登录 " + targetPlayerName + "!");
        
        String targetMessage = config.getString("messages.force-logged-in", "&a你已被管理员强制登录!");
        targetPlayer.sendMessage(ChatColor.translateAlternateColorCodes('&', targetMessage));
        
        getLogger().info("控制台已强制登录玩家 " + targetPlayerName);
        return true;
    }
}