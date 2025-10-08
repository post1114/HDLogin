## Security features


### Password encryption
- Use the SHA-256 salted hashing algorithm
- Each password has a unique salt value
- The hash value is different even if the password is the same


### Protection mechanisms
- Non-logged in players cannot move, attack, break blocks, use items or commands
- Only the '/login' and '/register' commands are available for players who are not logged in
- Login timeout automatically kicks out protection
- Failed attempt limits prevent brute force cracking


## Development Information


- **Minecraft version**: 1.8.8
- **Spigot API**: 1.8.8-R0.1-SNAPSHOT
- Java Version: 8
- **Build Tools**: Maven


## Troubleshooting


### FAQs


1. **Players cannot move or interact**
   - This is normal behavior and players need to log in first
   - Use the '/login' or '/register' commands


2. **Password Error Blocked**
   - Wait for the ban to end
   - Admins use '/unloginban' to unblock


3. **Plugin Fails to Load**
   - Check if the server is Spigot 1.8.8
   - Confirm that the Java version is 8 or above


## Technical Support


For questions or suggestions, please check:
1. Error messages in the server logs
2. Whether the profile is correct
3. Whether the permission settings are appropriate


---




**Note**: Please back up your player data files ('plugins/SimpleLogin/data.yml') regularly in case of data loss.
