export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "https://stacknest.site/blogpost/api"

export const apiEndpoints = {
  posts: `${API_BASE_URL}/api.php?action=posts`,
  login: `${API_BASE_URL}/api.php?action=login`,
  register: `${API_BASE_URL}/api.php?action=register`,
  verifyEmail: `${API_BASE_URL}/api.php?action=verify-email`,
  like: `${API_BASE_URL}/api.php?action=like`,
  comments: `${API_BASE_URL}/api.php?action=comments`,
  chatUsers: `${API_BASE_URL}/api.php?action=chat-users`,
  chatMessages: `${API_BASE_URL}/api.php?action=chat-messages`,
  sendMessage: `${API_BASE_URL}/api.php?action=send-message`,
  heartbeat: `${API_BASE_URL}/api.php?action=heartbeat`,
  onlineStatus: `${API_BASE_URL}/api.php?action=online-status`,
  profile: `${API_BASE_URL}/api.php?action=profile`,
  newsletterSubscribe: `${API_BASE_URL}/api.php?action=newsletter-subscribe`,
  captcha: `${API_BASE_URL}/captcha.php`,
  uploads: `${API_BASE_URL}/uploads`,
  adminPanel: `${API_BASE_URL}/panel.php`,
}

export const apiCall = async (url: string, options?: RequestInit) => {
  try {
    console.log("API Call:", { url, method: options?.method || 'GET' })

    const response = await fetch(url, {
      ...options,
      credentials: 'include', // Enable cookies/session for CORS

      headers: {
        "Content-Type": "application/json",
        ...options?.headers,
      },
    })

    console.log("API Response status:", response.status)

    if (!response.ok) {
      const errorText = await response.text()
      console.error("API Error Response:", errorText)
      throw new Error(`HTTP error! status: ${response.status}`)
    }

    const data = await response.json()
    console.log("API Response data:", data)
    return data
  } catch (error) {
    console.error("API call failed:", error)
    throw error
  }
}
