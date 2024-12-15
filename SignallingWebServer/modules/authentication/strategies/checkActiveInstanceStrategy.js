const CustomStrategy = require('passport-custom').Strategy;
const axios = require('axios');

module.exports = function (config) {
    return new CustomStrategy((req, callback) => {
        console.log('Checking active instance');
        
        if (config.ApiDomain) {
            const token = req.query.token;
            
            if (!token) {
                console.log('Authentication failed. No token provided');
                return callback(null, false);
            }

            axios.post(`https://${config.ApiDomain}/checkActiveInstance`, { licenseId: config.LicenseId }, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            })
                .then(response => {
                    if (response.status === 200) {
                        console.log('Authentication successful');
                        return callback(null, {});
                    } else {
                        console.log('Authentication failed');
                        return callback(null, false);
                    }
                })
                .catch(error => {
                    console.log(`Error during authentication: ${error}`);
                    return callback(null, false);
                });
        } else {
            console.warn('API domain is not set. Skipping authentication');
            return callback(null, {});
        }
    });
};