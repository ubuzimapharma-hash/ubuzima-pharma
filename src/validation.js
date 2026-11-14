import { articleHtmlHasText, sanitizeArticleHtml } from "./content.js";

export function validateProduct(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { error: "Product details must be an object." };
  }

  const optionalTextFields = [
    ["generic_name", "Generic name", 120],
    ["active_ingredient", "Active ingredient", 300],
    ["strength", "Strength", 80],
    ["dosage_form", "Dosage form", 80],
    ["pack_size", "Pack size", 120],
    ["manufacturer", "Manufacturer", 120],
    ["directions_for_use", "Directions for use", 2000],
    ["indications", "Indications and uses", 2000],
    ["warnings", "Warnings", 2000],
    ["storage_instructions", "Storage instructions", 500]
  ];
  const productDetails = {};
  for (const [field, label, maxLength] of optionalTextFields) {
    const rawValue = input[field];
    if (rawValue !== undefined && rawValue !== null && typeof rawValue !== "string") {
      return { error: `${label} must be text.` };
    }
    const value = typeof rawValue === "string" ? rawValue.trim() : "";
    if (value.length > maxLength) {
      return { error: `${label} must be at most ${maxLength} characters.` };
    }
    productDetails[field] = value || null;
  }

  const name = typeof input.name === "string" ? input.name.trim() : "";
  const category = typeof input.category === "string" ? input.category.trim() : "";
  const description = typeof input.description === "string" ? input.description.trim() : "";
  const rawImageUrl = input.image_url;
  const rawPrice = input.price_bif;
  const rawStock = input.stock_quantity;
  const available = input.is_available;

  if (!name || name.length > 120) return { error: "Name is required and must be at most 120 characters." };
  if (!category || category.length > 80) return { error: "Category is required and must be at most 80 characters." };
  if (!description || description.length > 500) return { error: "Description is required and must be at most 500 characters." };

  let imageUrl = null;
  if (rawImageUrl !== undefined && rawImageUrl !== null && rawImageUrl !== "") {
    if (typeof rawImageUrl !== "string" || rawImageUrl.length > 2048) {
      return { error: "Image URL must be a valid HTTPS URL of at most 2,048 characters." };
    }
    try {
      const parsedUrl = new URL(rawImageUrl.trim());
      if (parsedUrl.protocol !== "https:" || !parsedUrl.hostname) throw new Error();
      imageUrl = parsedUrl.href;
    } catch {
      return { error: "Image URL must be a valid HTTPS URL." };
    }
  }

  let price = null;
  if (rawPrice !== null && rawPrice !== undefined && rawPrice !== "") {
    const parsedPrice = typeof rawPrice === "number" ? rawPrice : Number(rawPrice);
    if (!Number.isSafeInteger(parsedPrice) || parsedPrice < 0 || parsedPrice > 999999999999) {
      return { error: "Price must be a non-negative whole number of BIF." };
    }
    price = parsedPrice;
  }

  const stockQuantity = rawStock === undefined || rawStock === "" ? 0 : Number(rawStock);
  if (!Number.isSafeInteger(stockQuantity) || stockQuantity < 0 || stockQuantity > 1000000) {
    return { error: "Stock must be a non-negative whole number up to 1,000,000." };
  }

  if (available !== undefined && typeof available !== "boolean" && available !== "true" && available !== "false") {
    return { error: "Availability must be a boolean." };
  }

  return {
    value: {
      name,
      category,
      description,
      imageUrl,
      priceBif: price,
      stockQuantity,
      isAvailable: available === undefined ? true : available === true || available === "true",
      ...productDetails
    }
  };
}

export function validatePatientRegistration(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { error: "Account details must be an object." };
  }
  const email = typeof input.email === "string" ? input.email.trim().toLowerCase() : "";
  const fullName = typeof input.full_name === "string" ? input.full_name.trim() : "";
  const phone = typeof input.phone === "string" ? input.phone.trim() : "";
  const password = typeof input.password === "string" ? input.password : "";
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { error: "Enter a valid email address." };
  }
  if (!fullName || fullName.length > 120) {
    return { error: "Full name is required and must be at most 120 characters." };
  }
  if (!phone || phone.length > 30) return { error: "Phone number is required and must be at most 30 characters." };
  if (password.length < 12 || Buffer.byteLength(password, "utf8") > 72) {
    return { error: "Password must be at least 12 characters and no more than 72 UTF-8 bytes." };
  }
  return { value: { email, fullName, phone, password } };
}

export function validateProfileDetails(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { error: "Profile details must be an object." };
  }
  const fullName = typeof input.full_name === "string" ? input.full_name.trim() : "";
  const phone = typeof input.phone === "string" ? input.phone.trim() : "";
  if (!fullName || fullName.length > 120 || /[\u0000-\u001f\u007f]/.test(fullName)) {
    return { error: "Full name is required and must be at most 120 characters." };
  }
  if (phone.length > 30 || /[\u0000-\u001f\u007f]/.test(phone)) {
    return { error: "Phone number must be at most 30 characters." };
  }
  return { value: { fullName, phone } };
}

export function validateOrderItems(input) {
  if (!Array.isArray(input) || input.length < 1 || input.length > 50) {
    return { error: "An order must contain between 1 and 50 products." };
  }
  const items = [];
  const seen = new Set();
  for (const item of input) {
    const productId = typeof item?.product_id === "string" ? item.product_id : "";
    const quantity = item?.quantity;
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(productId)) {
      return { error: "A product ID is invalid." };
    }
    if (seen.has(productId)) return { error: "Each product may only appear once in an order." };
    if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > 100) {
      return { error: "Product quantity must be a whole number between 1 and 100." };
    }
    seen.add(productId);
    items.push({ productId, quantity });
  }
  return { value: items };
}

export function validateStaffAccount(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { error: "Staff account details must be an object." };
  }
  const username = typeof input.email === "string" ? input.email.trim().toLowerCase() : "";
  const password = typeof input.password === "string" ? input.password : "";
  const role = input.role;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(username) || username.length > 254) {
    return { error: "Enter a valid staff email address." };
  }
  if (password.length < 12 || Buffer.byteLength(password, "utf8") > 72) {
    return { error: "Password must be at least 12 characters and no more than 72 UTF-8 bytes." };
  }
  if (!["admin", "pharmacist", "doctor"].includes(role)) return { error: "Role must be admin, pharmacist, or doctor." };
  return { value: { username, password, role } };
}

export function validateStaffInvitation(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { error: "Invitation details must be an object." };
  }
  const email = typeof input.email === "string" ? input.email.trim().toLowerCase() : "";
  const role = input.role;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return { error: "Enter a valid staff email address." };
  }
  if (!["admin", "pharmacist", "doctor"].includes(role)) return { error: "Role must be admin, pharmacist, or doctor." };
  return { value: { email, role } };
}

export function validateNewsArticle(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { error: "News details must be an object." };
  }
  const title = typeof input.title === "string" ? input.title.trim() : "";
  const summary = typeof input.summary === "string" ? input.summary.trim() : "";
  const body = typeof input.body === "string" ? sanitizeArticleHtml(input.body) : "";
  const videoUrl = typeof input.video_url === "string" ? input.video_url.trim() : "";
  const imageUrl = typeof input.image_url === "string" ? input.image_url.trim() : "";
  const category = typeof input.category === "string" ? input.category.trim() : "Ubuzima";
  const status = input.status === undefined ? "published" : input.status;
  const scheduledAt = typeof input.scheduled_at === "string" ? input.scheduled_at : "";

  if (!title || title.length > 180) return { error: "Title is required and must be at most 180 characters." };
  if (/[\u0000-\u001f\u007f]/.test(title)) return { error: "Title cannot contain line breaks or control characters." };
  if (!summary || summary.length > 500) return { error: "Summary is required and must be at most 500 characters." };
  if (!body || body.length > 50000 || !articleHtmlHasText(body)) return { error: "News text is required and must be at most 50,000 characters." };
  if (!["Ubuzima", "Ubuzima rusange", "Imiti", "Ubushakashatsi"].includes(category)) {
    return { error: "Choose a valid news category." };
  }
  if (!["draft", "pending_review", "scheduled", "published", "archived"].includes(status)) {
    return { error: "Choose a valid news status." };
  }
  if (status === "scheduled" && (!scheduledAt || !Number.isFinite(Date.parse(scheduledAt)))) {
    return { error: "A valid publication date is required for scheduled news." };
  }
  if (status !== "scheduled" && scheduledAt) return { error: "A publication date is only allowed for scheduled news." };
  if (imageUrl && (!imageUrl.startsWith("/uploads/") || imageUrl.includes("..") || /[\u0000-\u001f\u007f\\]/.test(imageUrl))) {
    return { error: "Enter a valid uploaded article image URL." };
  }
  if (videoUrl) {
    try {
      const url = new URL(videoUrl);
      const allowedHosts = new Set(["youtube.com", "www.youtube.com", "youtu.be", "www.youtube-nocookie.com", "player.vimeo.com", "vimeo.com", "www.vimeo.com"]);
      if (url.protocol !== "https:" || !allowedHosts.has(url.hostname.toLowerCase())) {
        return { error: "Video URL must be an HTTPS YouTube or Vimeo link." };
      }
    } catch {
      return { error: "Enter a valid HTTPS YouTube or Vimeo link." };
    }
  }
  return {
    value: {
      title,
      summary,
      body,
      videoUrl: videoUrl || null,
      imageUrl: imageUrl || null,
      category,
      status,
      scheduledAt: status === "scheduled" ? new Date(scheduledAt).toISOString() : null
    }
  };
}

export function validateVideo(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { error: "Video details must be an object." };
  }
  const title = typeof input.title === "string" ? input.title.trim() : "";
  const description = typeof input.description === "string" ? input.description.trim() : "";
  const category = typeof input.category === "string" ? input.category.trim() : "";
  const status = input.status === undefined ? "draft" : input.status;
  const scheduledAt = typeof input.scheduled_at === "string" ? input.scheduled_at : "";
  const videoUrl = typeof input.video_url === "string" ? input.video_url.trim() : "";
  const sourceType = input.source_type;
  const thumbnailUrl = typeof input.thumbnail_url === "string" ? input.thumbnail_url.trim() : "";

  if (!title || title.length > 180) return { error: "Video title is required and must be at most 180 characters." };
  if (!description || description.length > 1000) return { error: "Video description is required and must be at most 1,000 characters." };
  if (!category || category.length > 60) return { error: "Video category is required and must be at most 60 characters." };
  if (!["upload", "youtube", "vimeo"].includes(sourceType)) return { error: "Choose a valid video source." };
  if (!["draft", "scheduled", "published", "archived"].includes(status)) return { error: "Choose a valid video status." };
  if (status === "scheduled" && (!scheduledAt || !Number.isFinite(Date.parse(scheduledAt)))) {
    return { error: "A valid publication date is required for scheduled videos." };
  }
  if (status !== "scheduled" && scheduledAt) return { error: "A publication date is only allowed for scheduled videos." };
  if (sourceType === "upload" && !/^\/uploads\/videos\/[0-9a-f-]+\.(mp4|webm)$/.test(videoUrl)) {
    return { error: "Upload an MP4 or WebM video." };
  }
  if (sourceType !== "upload") {
    try {
      const url = new URL(videoUrl);
      const hosts = sourceType === "youtube"
        ? new Set(["youtube.com", "www.youtube.com", "youtu.be", "www.youtube-nocookie.com"])
        : new Set(["vimeo.com", "www.vimeo.com", "player.vimeo.com"]);
      if (url.protocol !== "https:" || !hosts.has(url.hostname.toLowerCase())) return { error: "Enter a valid HTTPS video URL." };
    } catch {
      return { error: "Enter a valid HTTPS video URL." };
    }
  }
  if (thumbnailUrl) {
    try {
      const url = new URL(thumbnailUrl, "https://ubuzimapharma.invalid");
      if (!url.pathname.startsWith("/uploads/") && url.protocol !== "https:") return { error: "Thumbnail must be an HTTPS image URL." };
    } catch {
      return { error: "Enter a valid thumbnail URL." };
    }
  }
  return {
    value: {
      title,
      description,
      category,
      status,
      scheduledAt: status === "scheduled" ? new Date(scheduledAt).toISOString() : null,
      sourceType,
      videoUrl,
      thumbnailUrl: thumbnailUrl || null
    }
  };
}
