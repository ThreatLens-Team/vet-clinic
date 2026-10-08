import { logSecurityEvent } from "./securityLogger.js";

export function requireAuth(req, res, next) {
	/*
		Stop here if there is no logged-in user stored in the session.
		That means this request is coming from someone not authenticated.
	*/
	if (!req.session?.userID) {
		/*
			Record an attempt to access an authenticated route
			without a valid logged-in session.
		*/
		logSecurityEvent({
			event_type: "UNAUTHORIZED_ACCESS",
			result: "FAILURE",
			user_id: null,
			email: null,
			user_type: null,
			source_ip: req.ip,
			reason: "NOT_AUTHENTICATED",
			http_status: 401,
			http_method: req.method,
			route: req.originalUrl,
			required_role: "AUTHENTICATED",
		});
		return res.status(401).json({ message: "not authenticated" });
	}

	/*
		The session has a userID, so allow the request to continue
		to the next middleware or route handler.
	*/
	next();
}

function getSessionUserType(req) {
	/*
		Read the userType from the session and normalize it so checks
		are consistent even if spacing or letter casing differs.
	*/
	return String(req.session?.userType || "").trim().toUpperCase();
}

export function requireAdmin(req, res, next) {
	/*
		First make sure the request is coming from a logged-in user.
		There is no point checking admin access if nobody is authenticated.
	*/
	if (!req.session?.userID) {
		/*
			Record an unauthenticated attempt to access
			a route that requires the ADMIN role.
		*/
		logSecurityEvent({
			event_type: "UNAUTHORIZED_ACCESS",
			result: "FAILURE",
			user_id: null,
			email: null,
			user_type: null,
			source_ip: req.ip,
			reason: "NOT_AUTHENTICATED",
			http_status: 401,
			http_method: req.method,
			route: req.originalUrl,
			required_role: "ADMIN",
		});
		return res.status(401).json({ message: "not authenticated" });
	}

	/*
		Get the normalized user type from the session so we can check
		whether this authenticated user is actually an admin.
	*/
	const userType = getSessionUserType(req);

	/*
		Block access if the user is logged in but is not an admin.
		This is a permissions failure, not an authentication failure.
	*/
	if (userType !== "ADMIN") {
		/*
			Record an authenticated user attempting to access
            a route that requires the ADMIN role.
		*/
		logSecurityEvent({
			event_type: "UNAUTHORIZED_ACCESS",
			result: "FAILURE",
			user_id: req.session.userID,
			email: req.session.email ?? null,
			user_type: userType,
			source_ip: req.ip,
			reason: "INSUFFICIENT_ROLE",
			http_status: 403,
			http_method: req.method,
			route: req.originalUrl,
			required_role: "ADMIN",
		});
		return res.status(403).json({ message: "forbidden" });
	}
	/*
		The user is authenticated and has the correct admin role,
		so allow the request to continue.
	*/
	next();
}

export function requireStaff(req, res, next) {
	/*
		First make sure the request is coming from a logged-in user.
		There is no point checking staff access if nobody is authenticated.
	*/
	if (!req.session?.userID) {
		/*
			Record an unauthenticated attempt to access
            a route that requires the STAFF role.
		*/
		logSecurityEvent({
			event_type: "UNAUTHORIZED_ACCESS",
			result: "FAILURE",
			user_id: null,
			email: null,
			user_type: null,
			source_ip: req.ip,
			reason: "NOT_AUTHENTICATED",
			http_status: 401,
			http_method: req.method,
			route: req.originalUrl,
			required_role: "STAFF",
		});

		return res.status(401).json({ message: "not authenticated" });
	}

	/*
		Get the normalized user type from the session so we can check
		whether this authenticated user is actually staff.
	*/
	const userType = getSessionUserType(req);

	/*
		Block access if the user is logged in but is not staff.
		This is a permissions failure, not an authentication failure.
	*/
	if (userType !== "STAFF") {
		/*
			Record an authenticated user attempting to access
			a route that requires the STAFF role.
		*/

		logSecurityEvent({
			event_type: "UNAUTHORIZED_ACCESS",
			result: "FAILURE",
			user_id: req.session.userID,
			email: req.session.email ?? null,
			user_type: userType,
			source_ip: req.ip,
			reason: "INSUFFICIENT_ROLE",
			http_status: 403,
			http_method: req.method,
			route: req.originalUrl,
			required_role: "STAFF",
		});
		return res.status(403).json({ message: "forbidden" });
	}

	/*
		The user is authenticated and has the correct staff role,
		so allow the request to continue.
	*/
	next();
}