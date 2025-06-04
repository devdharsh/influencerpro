# influencerpro
INFLUENCERPRO is a web application developed by me during my college. In this application, influencers and sponsors can register themselves to search for new advertisement and advertisers for some particular brands. Also there is an admin to maintain all this stuffs.

ARCHITECTURES AND FEATURES: 
1. Authentication System: 
o Separate Logins: Different login pages for Admins and Users (Influencers and Sponsors). 
o Role-Based Access: Ensures users only access features relevant to their role.

2. Dashboards: 
o Admin Dashboard: Manages campaigns, users, and platform analytics. Includes a control panel for viewing active campaigns and flagged content. 
o Influencer Dashboard: Displays active campaigns, profile details, and request management. 
o Sponsor Dashboard: Allows sponsors to create and manage campaigns, view requests, and monitor performance.

3. Campaign Management: 
o Create & Edit Campaigns: Sponsors can add details like title, description, and budget. 
o Request Handling: Influencers can request to join campaigns, and sponsors can invite influencers.

4. Profile Management: 
o Editable Profiles: Users can update their information and view personalized stats.

5. Request & Flag Management: 
o Request Status: Track the status of campaign-related requests (pending, accepted, rejected). 
o Flagging System: Users can flag inappropriate content, which admins can manage.

6. Statistics & Analytics: 
o Visual Data: Real-time campaign performance, engagement metrics, and platform usage stats are displayed through charts and graphs.

API ENDPOINTS: 

1. `/login`: Authenticates user and redirects to the appropriate dashboard based on their role. 
2. `/logout`: Logs out the user and clears session data. 
3. `/profile`: Displays the profile page with active campaigns and requests for the logged-in user. 
4. `/update_profile`: Updates user profile information, including handling file uploads for profile pictures. 
5. `/find`: Displays campaigns and allows users to request to join them. 
6. `/profile/<int:user_id>`: Displays the profile of the specified user, including their campaigns. 
7. `/update_request/<int:request_id>`: Updates the status of a campaign request. 
8. `/flag/<int:item_id>/<item_type>`: Flags a user or campaign with a reason. 
9. `/remove_flag/<int:flag_id>`: Removes a flag from the system. 
10. `/remove_campaign/<int:campaign_id>`: Temporarily removes a campaign from visibility. 
11. `/update_campaign/<int:campaign_id>`: Updates the details of a campaign, including uploading a new image. 
12. `/admin_dashboard/info`: Displays information about ongoing campaigns and flagged items in the admin dashboard. 
13. `/admin_dashboard/find`: Allows administrators to search for users and campaigns based on a query. 
14. `/stats`: Displays statistics on users and campaigns, including platform and category breakdowns. 
15. `/update_profile`: Handles profile picture uploads during profile updates.
