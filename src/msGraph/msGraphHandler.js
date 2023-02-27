class msGraphHandler {

    static ValidateUser(user) {
        logger.info(`[msGraph][CN=${user['CN']}] user['emailAddress'])`);
        return true;
    }
}

export default msGraphHandler;